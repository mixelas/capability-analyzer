import * as ts from "typescript";
import * as fs from "fs";
import * as path from "path";

export type Sink = {
  type: string;
  file: string;
  line: number;
  column: number;
  dynamic?: boolean;
  tainted?: boolean;
};

export type ToolReport = {
  toolName: string;
  file: string;
  sinks: Sink[];
};

function isToolCall(node: ts.CallExpression): boolean {
  const expr = node.expression;
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text === "tool";
  }
  return false;
}

function getStringLiteralValue(node?: ts.Expression): string | undefined {
  if (!node) return undefined;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return undefined;
}

function locationOf(node: ts.Node, sourceFile: ts.SourceFile) {
  const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return { line: pos.line + 1, column: pos.character + 1 };
}

function collectSinksInFunction(func: ts.FunctionLikeDeclaration | ts.ArrowFunction, sourceFile: ts.SourceFile): Sink[] {
  const sinks: Sink[] = [];

  // simple intraprocedural taint tracking
  const tainted = new Set<string>();

  function isRequestArgumentsAccess(node: ts.Node): boolean {
    // match patterns like req.params.arguments[...] or request.params.arguments[...] or req.params.arguments.X
    if (ts.isPropertyAccessExpression(node)) {
      const name = node.name.text;
      if (name === "arguments") return true;
      return isRequestArgumentsAccess(node.expression);
    }
    if (ts.isElementAccessExpression(node)) {
      return isRequestArgumentsAccess(node.expression) || (node.argumentExpression ? isRequestArgumentsAccess(node.argumentExpression) : false);
    }
    return false;
  }

  function exprTainted(expr: ts.Expression | undefined): boolean {
    if (!expr) return false;
    if (ts.isIdentifier(expr)) return tainted.has(expr.text);
    if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
      if (isRequestArgumentsAccess(expr)) return true;
      // property chain like foo.bar where foo is tainted
      const left = ts.isPropertyAccessExpression(expr) ? expr.expression : expr.expression;
      return exprTainted(left as ts.Expression);
    }
    if (ts.isBinaryExpression(expr)) return exprTainted(expr.left as ts.Expression) || exprTainted(expr.right as ts.Expression);
    if (ts.isTemplateExpression(expr)) {
      for (const span of expr.templateSpans) if (exprTainted(span.expression)) return true;
      return false;
    }
    if (ts.isCallExpression(expr)) {
      // simple: if any arg tainted
      for (const a of expr.arguments) if (exprTainted(a as ts.Expression)) return true;
      return false;
    }
    return false;
  }

  function markAssignment(nameNode: ts.Node | undefined, initializer?: ts.Expression) {
    if (!nameNode) return;
    // only handle simple identifier lhs
    if (ts.isIdentifier(nameNode)) {
      const id = nameNode.text;
      if (!initializer) return;
      if (exprTainted(initializer) || isRequestArgumentsAccess(initializer)) {
        tainted.add(id);
      }
    }
  }

  function visit(n: ts.Node) {
    // track variable declarations
    if (ts.isVariableStatement(n)) {
      for (const decl of n.declarationList.declarations) {
        if (ts.isIdentifier(decl.name)) markAssignment(decl.name, decl.initializer as ts.Expression | undefined);
      }
    }

    if (ts.isVariableDeclaration(n)) {
      if (ts.isIdentifier(n.name)) markAssignment(n.name, n.initializer as ts.Expression | undefined);
    }

    // assignments like a = ...
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      markAssignment(n.left, n.right as ts.Expression);
    }

    if (ts.isCallExpression(n)) {
      // child_process.exec / spawn
      let pushed: Sink | null = null;
      if (ts.isPropertyAccessExpression(n.expression)) {
        const left = n.expression.expression;
        const name = n.expression.name.text;
        if (ts.isIdentifier(left) && left.text === "child_process" && ["exec", "spawn", "execSync", "spawnSync"].includes(name)) {
          const loc = locationOf(n, sourceFile);
          pushed = { type: `child_process.${name}`, file: sourceFile.fileName, line: loc.line, column: loc.column, dynamic: true, tainted: false };
        }
        if (ts.isIdentifier(left) && left.text === "axios") {
          const loc = locationOf(n, sourceFile);
          pushed = { type: `axios.${name}`, file: sourceFile.fileName, line: loc.line, column: loc.column, dynamic: true, tainted: false };
        }
      }

      // require('child_process').exec pattern
      if (!pushed && ts.isPropertyAccessExpression(n.expression) && ts.isCallExpression(n.expression.expression)) {
        const call = n.expression.expression;
        if (ts.isIdentifier(call.expression) && call.expression.text === "require") {
          const arg = call.arguments[0];
          const moduleName = getStringLiteralValue(arg as ts.Expression);
          if (moduleName === "child_process") {
            const name = n.expression.name.text;
            const loc = locationOf(n, sourceFile);
            pushed = { type: `child_process.${name}`, file: sourceFile.fileName, line: loc.line, column: loc.column, dynamic: true, tainted: false };
          }
        }
      }

      // fs.readFile / writeFile etc
      if (!pushed && ts.isPropertyAccessExpression(n.expression)) {
        const left = n.expression.expression;
        const name = n.expression.name.text;
        if (ts.isIdentifier(left) && left.text === "fs" && ["readFile", "writeFile", "readFileSync", "writeFileSync", "unlink"].includes(name)) {
          const arg0 = n.arguments[0];
          const loc = locationOf(n, sourceFile);
          const isDynamic = !(arg0 && ts.isStringLiteral(arg0));
          pushed = { type: `fs.${name}`, file: sourceFile.fileName, line: loc.line, column: loc.column, dynamic: isDynamic, tainted: false };
          if (exprTainted(arg0 as ts.Expression) || isRequestArgumentsAccess(arg0 as ts.Node)) pushed.tainted = true;
        }
      }

      // fetch(...) or axios(...) or eval(...)
      if (!pushed && ts.isIdentifier(n.expression)) {
        const id = n.expression.text;
        if (id === "fetch") {
          const arg0 = n.arguments[0];
          const loc = locationOf(n, sourceFile);
          const isDynamic = !(arg0 && ts.isStringLiteral(arg0));
          pushed = { type: "fetch", file: sourceFile.fileName, line: loc.line, column: loc.column, dynamic: isDynamic, tainted: false };
          if (exprTainted(arg0 as ts.Expression) || isRequestArgumentsAccess(arg0 as ts.Node)) pushed.tainted = true;
        }
        if (id === "axios") {
          const arg0 = n.arguments[0];
          const loc = locationOf(n, sourceFile);
          const isDynamic = !(arg0 && ts.isStringLiteral(arg0));
          pushed = { type: "axios", file: sourceFile.fileName, line: loc.line, column: loc.column, dynamic: isDynamic, tainted: false };
          if (exprTainted(arg0 as ts.Expression) || isRequestArgumentsAccess(arg0 as ts.Node)) pushed.tainted = true;
        }
        if (id === "eval") {
          const loc = locationOf(n, sourceFile);
          pushed = { type: "eval", file: sourceFile.fileName, line: loc.line, column: loc.column, dynamic: true, tainted: false };
          if (n.arguments.some(a => exprTainted(a as ts.Expression) || isRequestArgumentsAccess(a as ts.Node))) pushed.tainted = true;
        }
      }

      if (pushed) sinks.push(pushed);
    }

    if (ts.isNewExpression(n)) {
      if (ts.isIdentifier(n.expression) && n.expression.text === "Function") {
        const loc = locationOf(n, sourceFile);
        const pushed: Sink = { type: "new Function", file: sourceFile.fileName, line: loc.line, column: loc.column, dynamic: true, tainted: true };
        sinks.push(pushed);
      }
    }

    ts.forEachChild(n, visit);
  }

  if (func.body) ts.forEachChild(func.body, visit);
  return sinks;
}

export function analyzeDirectory(targetPath: string): ToolReport[] {
  const entries: string[] = [];
  function walk(dir: string) {
    const names = fs.readdirSync(dir);
    for (const name of names) {
      const full = path.join(dir, name);
      const st = fs.statSync(full);
      if (st.isDirectory()) walk(full);
      else if (/\.(js|ts|jsx|tsx)$/.test(name)) entries.push(full);
    }
  }
  walk(targetPath);

  const program = ts.createProgram(entries, { allowJs: true, target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.CommonJS });
  const checker = program.getTypeChecker();

  const reports: ToolReport[] = [];

  for (const sourceFile of program.getSourceFiles()) {
    if (!sourceFile.fileName.startsWith(targetPath)) continue; // skip libs

    ts.forEachChild(sourceFile, function visit(node) {
      if (ts.isCallExpression(node) && isToolCall(node)) {
        const args = node.arguments;
        const nameArg = args[0];
        let toolName = "<unknown>";
        const textName = getStringLiteralValue(nameArg as ts.Expression);
        if (textName) toolName = textName;
        const handlerArg = args[2];
        const report: ToolReport = { toolName, file: sourceFile.fileName, sinks: [] };

        if (handlerArg) {
          // inline function
          if (ts.isFunctionExpression(handlerArg) || ts.isArrowFunction(handlerArg)) {
            const sinks = collectSinksInFunction(handlerArg, sourceFile);
            report.sinks.push(...sinks);
          } else if (ts.isIdentifier(handlerArg)) {
            // try to resolve function declaration in same file
            const sym = checker.getSymbolAtLocation(handlerArg);
            if (sym && sym.declarations) {
              for (const d of sym.declarations) {
                if (ts.isFunctionDeclaration(d) || ts.isVariableDeclaration(d) || ts.isFunctionExpression(d)) {
                  // variable of function type
                  if (ts.isVariableDeclaration(d) && d.initializer && (ts.isFunctionExpression(d.initializer) || ts.isArrowFunction(d.initializer))) {
                    const sinks = collectSinksInFunction(d.initializer as ts.ArrowFunction, sourceFile);
                    report.sinks.push(...sinks);
                  }
                  if (ts.isFunctionDeclaration(d)) {
                    const sinks = collectSinksInFunction(d as ts.FunctionDeclaration, sourceFile);
                    report.sinks.push(...sinks);
                  }
                }
              }
            }
          }
        }

        if (report.sinks.length > 0) reports.push(report);
      }

      ts.forEachChild(node, visit);
    });
  }

  return reports;
}

export function runAndPrint(targetPath: string) {
  const reports = analyzeDirectory(targetPath);
  const out = { scanned: targetPath, count: reports.length, reports };
  console.log(JSON.stringify(out, null, 2));
}
