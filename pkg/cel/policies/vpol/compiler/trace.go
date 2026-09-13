package compiler

import (
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
)

type TraceEntry struct {
	ExpressionID int64
	Expression   string
	Value        ref.Val
}

func collectTrace(ast *cel.Ast, state interpreter.EvalState) ([]TraceEntry, error) {
	if ast == nil || state == nil {
		return nil, nil
	}

	nativeAST := ast.NativeRep()
	traces := make([]TraceEntry, 0)

	celast.PreOrderVisit(nativeAST.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		value, found := state.Value(e.ID())
		if !found {
			return
		}
		exprStr, err := cel.ExprToString(e, nativeAST.SourceInfo())
		if err != nil {
			return
		}
		traces = append(traces, TraceEntry{
			ExpressionID: e.ID(),
			Expression:   exprStr,
			Value:        value,
		})
	}))
	return traces, nil
}
