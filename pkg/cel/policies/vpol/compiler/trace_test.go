package compiler

import (
	"context"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectTrace(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
	)
	require.NoError(t, err)

	source := `request.user == "admin" && request.namespace == "prod"`

	compiledAST, issues := env.Compile(source)
	require.NoError(t, issues.Err())

	program, err := env.Program(
		compiledAST,
		cel.EvalOptions(cel.OptTrackState),
	)
	require.NoError(t, err)

	input := map[string]any{
		"request": map[string]any{
			"user":      "admin",
			"namespace": "prod",
		},
	}

	_, details, err := program.ContextEval(context.Background(), input)
	require.NoError(t, err)
	require.NotNil(t, details)

	traces, err := collectTrace(compiledAST, details.State())
	require.NoError(t, err)

	assert.NotEmpty(t, traces)

	expressions := make(map[string]any)
	for _, trace := range traces {
		expressions[trace.Expression] = trace.Value
	}

	assert.Contains(t, expressions, `request.user == "admin"`)
	assert.Contains(t, expressions, `request.namespace == "prod"`)
	assert.Contains(t, expressions, `request.user`)
	assert.Contains(t, expressions, `request.namespace`)
}
