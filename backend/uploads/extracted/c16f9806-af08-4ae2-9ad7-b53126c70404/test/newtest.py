import ast


class TaintChecker(ast.NodeVisitor):

    def __init__(self):
        self.tainted = set()
        self.vulnerabilities = []

    # --------------------------
    # Assignment Tracking
    # --------------------------
    def visit_Assign(self, node):

        # Case 1: input() → tainted
        if isinstance(node.value, ast.Call):
            if self.get_func_name(node.value.func) == "input":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted.add(target.id)

        # Case 2: propagation (x = y or x = "hello" + y)
        if self.is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)

        self.generic_visit(node)

    # --------------------------
    # Function Call Checking
    # --------------------------
    def visit_Call(self, node):

        func_name = self.get_func_name(node.func)

        # 🔥 SQL Injection (cursor.execute)
        if func_name == "execute":
            for arg in node.args:
                if self.is_tainted(arg):
                    self.vulnerabilities.append(
                        f"SQL Injection detected at line {node.lineno}"
                    )

        # 🔥 Command Injection (os.system, subprocess)
        if func_name in {"system", "popen", "call"}:
            for arg in node.args:
                if self.is_tainted(arg):
                    self.vulnerabilities.append(
                        f"Command Injection detected at line {node.lineno}"
                    )

        self.generic_visit(node)

    # --------------------------
    # Taint Detection Logic
    # --------------------------
    def is_tainted(self, node):

        # Variable
        if isinstance(node, ast.Name):
            return node.id in self.tainted

        # String concatenation
        if isinstance(node, ast.BinOp):
            return self.is_tainted(node.left) or self.is_tainted(node.right)

        # f-string
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if self.is_tainted(value.value):
                        return True

        # format() usage
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "format":
                    for arg in node.args:
                        if self.is_tainted(arg):
                            return True

        return False

    def get_func_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""

    # --------------------------
    # Report
    # --------------------------
    def report(self):
        if not self.vulnerabilities:
            print("No vulnerabilities detected.")
        else:
            print("Vulnerabilities Found:")
            for v in self.vulnerabilities:
                print(v)


# --------------------------
# Run the checker
# --------------------------
if __name__ == "__main__":
    with open("test.py", "r") as f:
        tree = ast.parse(f.read())

    checker = TaintChecker()
    checker.visit(tree)
    checker.report()