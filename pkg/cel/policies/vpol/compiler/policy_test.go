package compiler

import (
	"context"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"github.com/kyverno/kyverno/pkg/cel/compiler"
	"github.com/stretchr/testify/assert"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apiserver/pkg/cel/lazy"
)

// mockVpolProgram is a lightweight cel.Program stub for unit tests.
type mockVpolProgram struct {
	retVal ref.Val
	err    error
}

func (m *mockVpolProgram) ContextEval(_ context.Context, _ any) (ref.Val, *cel.EvalDetails, error) {
	return m.retVal, nil, m.err
}

func (m *mockVpolProgram) Eval(any) (ref.Val, *cel.EvalDetails, error) {
	return m.retVal, nil, m.err
}

func (m *mockVpolProgram) ConcurrentEval(_ context.Context, _ any) <-chan cel.EvalResult {
	return nil
}

// TestEvaluateWithData_FullExemptionPrecedence is a regression test for
// https://github.com/kyverno/kyverno/issues/16053.
//
// When multiple PolicyExceptions match a resource, a full-exemption exception
// (one with no Images and no AllowedValues) must cause the evaluation loop to
// break and indicate a full exemption, regardless of whether a partial
// exception also matched.
func TestEvaluateWithData_FullExemptionPrecedence(t *testing.T) {
	t.Run("full-exemption takes precedence over partial exception", func(t *testing.T) {
		partialEx := &policiesv1beta1.PolicyException{
			Spec: policiesv1beta1.PolicyExceptionSpec{
				Images: []string{"nginx:*"},
			},
		}
		fullEx := &policiesv1beta1.PolicyException{
			Spec: policiesv1beta1.PolicyExceptionSpec{
				// no Images, no AllowedValues → full exemption
			},
		}

		p := &Policy{
			exceptions: []compiler.Exception{
				// partial exception is matched first
				{MatchConditions: []cel.Program{}, Exception: partialEx},
				// full exemption is matched second – must still win
				{MatchConditions: []cel.Program{}, Exception: fullEx},
			},
		}

		result, err := p.evaluateWithData(context.Background(), evaluationData{})

		assert.NoError(t, err)
		// The full exemption breaks the loop (resetting any prior partial scopes),
		// and the post-loop check returns with exceptions; no validation is run.
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Exceptions)
		assert.False(t, result.Result, "validation should not have run")
	})

	t.Run("full-exemption takes precedence when appearing first", func(t *testing.T) {
		partialEx := &policiesv1beta1.PolicyException{
			Spec: policiesv1beta1.PolicyExceptionSpec{
				Images: []string{"nginx:*"},
			},
		}
		fullEx := &policiesv1beta1.PolicyException{
			Spec: policiesv1beta1.PolicyExceptionSpec{
				// no Images, no AllowedValues → full exemption
			},
		}

		p := &Policy{
			exceptions: []compiler.Exception{
				// full exemption is matched first
				{MatchConditions: []cel.Program{}, Exception: fullEx},
				// partial exception is matched second
				{MatchConditions: []cel.Program{}, Exception: partialEx},
			},
		}

		result, err := p.evaluateWithData(context.Background(), evaluationData{})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Exceptions)
		assert.False(t, result.Result, "validation should not have run")
	})

	t.Run("partial exception alone does not skip evaluation", func(t *testing.T) {
		partialEx := &policiesv1beta1.PolicyException{
			Spec: policiesv1beta1.PolicyExceptionSpec{
				Images: []string{"nginx:*"},
			},
		}

		// A single validation that always returns true.
		alwaysPass := &mockVpolProgram{retVal: types.Bool(true)}

		p := &Policy{
			exceptions: []compiler.Exception{
				{MatchConditions: []cel.Program{}, Exception: partialEx},
			},
			validations: []compiler.Validation{
				{Program: alwaysPass},
			},
		}

		result, err := p.evaluateWithData(context.Background(), evaluationData{})

		// A partial exception alone must NOT skip validation; the policy is evaluated.
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Result, "validation should have run and passed")
	})

	t.Run("all matched exceptions collected when priority labels and reportResult differ", func(t *testing.T) {
		// Regression guard for the exhaustive-loop requirement from the maintainer review:
		// matchedExceptions must be complete so the engine can (a) pick the
		// highest-priority exception via polex.kyverno.io/priority and (b) build
		// the user-facing message that lists every matched exception key.
		//
		// highPriorityEx has priority=10 (the winner for report selection).
		// laterEx has a lower priority but carries reportResult: pass, which
		// would silently override the skip result if the engine only saw *it*.
		// With the old break-based loop the second exception was never collected;
		// with the flag-based loop both must appear in result.Exceptions.
		highPriorityEx := &policiesv1beta1.PolicyException{
			Spec: policiesv1beta1.PolicyExceptionSpec{
				// full exemption – no Images, no AllowedValues
			},
		}
		highPriorityEx.SetLabels(map[string]string{
			"polex.kyverno.io/priority": "10",
		})

		laterEx := &policiesv1beta1.PolicyException{
			Spec: policiesv1beta1.PolicyExceptionSpec{
				// full exemption as well; carries reportResult: pass
				ReportResult: "pass",
			},
		}
		laterEx.SetLabels(map[string]string{
			"polex.kyverno.io/priority": "5",
		})

		p := &Policy{
			exceptions: []compiler.Exception{
				// high-priority exception is first in iteration order
				{MatchConditions: []cel.Program{}, Exception: highPriorityEx},
				// lower-priority exception with reportResult: pass comes second
				{MatchConditions: []cel.Program{}, Exception: laterEx},
			},
		}

		result, err := p.evaluateWithData(context.Background(), evaluationData{})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		// Both exceptions must be present so the engine sees the complete set.
		assert.Len(t, result.Exceptions, 2, "both exceptions must be collected by the exhaustive loop")
	})
}

func TestCompileValidationAndCollectTrace(t *testing.T) {
	policy := &policiesv1beta1.ValidatingPolicy{
		Spec: policiesv1beta1.ValidatingPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{},
			Validations: []admissionregistrationv1.Validation{
				{
					Expression: `object.metadata.name == "nginx"`,
				},
			},
		},
	}

	compiled, errs := NewCompiler().Compile(policy, nil)
	assert.Empty(t, errs)
	assert.NotNil(t, compiled)
	assert.Len(t, compiled.validations, 1)

	validation := compiled.validations[0]

	// Our AST-retention change.
	assert.NotNil(t, validation.AST)

	// Execute the real compiled CEL program.
	data := evaluationData{
		Object: map[string]any{
			"metadata": map[string]any{
				"name": "nginx",
			},
		},
		Variables: lazy.NewMapValue(compiler.VariablesType),
	}

	dataNew := map[string]any{
		compiler.ObjectKey:    data.Object,
		compiler.VariablesKey: data.Variables,
	}

	out, details, err := validation.Program.ContextEval(context.Background(), dataNew)

	assert.NoError(t, err)
	assert.NotNil(t, details)
	assert.Equal(t, types.Bool(true), out)

	trace, err := collectTrace(validation.AST, details.State())
	assert.NoError(t, err)
	assert.NotEmpty(t, trace)

	t.Logf("trace: %+v", trace)

	// The root expression must have been recorded.
	found := false
	for _, entry := range trace {
		if entry.Expression == `object.metadata.name == "nginx"` {
			found = true
			break
		}
	}

	assert.True(t, found, "expected validation expression in trace")
}

func TestCompileValidationAndCollectTrace_ComplexExpression(t *testing.T) {
	expression := `
		request.operation == "CREATE" &&
		(
			object.metadata.name.startsWith("prod-") ||
			object.metadata.labels.exists(k, k == "environment")
		) &&
		(
			object.spec.replicas > 0 &&
			object.spec.replicas <= 10
		) &&
		(
			object.spec.containers.all(
				c,
				c.image != "" &&
				(
					c.image.startsWith("registry.example.com/") ||
					c.image.startsWith("ghcr.io/")
				)
			)
		) &&
		(
			object.metadata.labels["team"] == "platform"
				? object.spec.replicas >= 2
				: object.spec.replicas == 1
		)
	`

	policy := &policiesv1beta1.ValidatingPolicy{
		Spec: policiesv1beta1.ValidatingPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{},
			Validations: []admissionregistrationv1.Validation{
				{
					Expression: expression,
				},
			},
		},
	}

	compiled, errs := NewCompiler().Compile(policy, nil)
	assert.Empty(t, errs)
	assert.NotNil(t, compiled)
	assert.Len(t, compiled.validations, 1)

	validation := compiled.validations[0]

	assert.NotNil(t, validation.AST)
	assert.NotNil(t, validation.Program)

	data := evaluationData{
		Object: map[string]any{
			"metadata": map[string]any{
				"name": "prod-api",
				"labels": map[string]any{
					"environment": "prod",
					"team":        "platform",
				},
			},
			"spec": map[string]any{
				"replicas": int64(3),
				"containers": []any{
					map[string]any{
						"image": "registry.example.com/api:v1",
					},
					map[string]any{
						"image": "ghcr.io/sidecar:v2",
					},
				},
			},
		},
		Request: map[string]any{
			"operation": "CREATE",
		},
		Variables: lazy.NewMapValue(compiler.VariablesType),
	}

	dataNew := map[string]any{
		compiler.ObjectKey:    data.Object,
		compiler.RequestKey:   data.Request,
		compiler.VariablesKey: data.Variables,
	}

	out, details, err := validation.Program.ContextEval(
		context.Background(),
		dataNew,
	)

	assert.NoError(t, err)
	assert.NotNil(t, details)
	assert.Equal(t, types.Bool(true), out)

	trace, err := collectTrace(validation.AST, details.State())
	assert.NoError(t, err)
	assert.NotEmpty(t, trace)

	t.Logf("=== COMPLEX TRACE ===")

	seenIDs := make(map[int64]bool)

	for _, entry := range trace {
		t.Logf(
			"ID=%d Expression=%s Value=%v",
			entry.ExpressionID,
			entry.Expression,
			entry.Value,
		)

		assert.False(
			t,
			seenIDs[entry.ExpressionID],
			"duplicate expression ID %d",
			entry.ExpressionID,
		)

		seenIDs[entry.ExpressionID] = true
	}

	expectedExpressions := []string{
		`request.operation == "CREATE"`,
		`object.metadata.name.startsWith("prod-")`,
		`object.spec.replicas > 0`,
		`object.spec.replicas <= 10`,
		`c.image != ""`,
		`c.image.startsWith("registry.example.com/")`,
		`c.image.startsWith("ghcr.io/")`,
		`object.metadata.labels["team"] == "platform"`,
		`object.spec.replicas >= 2`,
	}

	for _, expected := range expectedExpressions {
		found := false

		for _, entry := range trace {
			if entry.Expression == expected {
				found = true
				break
			}
		}

		assert.True(t, found, "expected expression %q in trace", expected)
	}
}
