import sys
import json
import ast
import argparse
import re
from pathlib import Path

def extract_routes_from_ast(app_path: Path):
    routes = []
    tree = ast.parse(app_path.read_text(encoding="utf-8"))
    
    for node in ast.walk(tree):
        # Handle module-level route registrations via decorators on functions
        # and also detect path parameters like <output_digest>.
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                # Handle @app.get("/path"), @app.post("/path"), @app.put("/path")
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if isinstance(decorator.func.value, ast.Name) and decorator.func.value.id == "app":
                        method = decorator.func.attr # "get", "post", "put"
                        if method in {"get", "post", "put", "delete", "patch"}:
                            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                                path = decorator.args[0].value
                                routes.append((path, method.upper(), node.name))
    return routes

def _normalize_path(path: str) -> str:
    # Convert Flask-style <param> segments to OpenAPI {param} segments.
    return re.sub(r"<([^>]+)>", r"{\1}", path)

def _extract_path_params(path: str):
    params = []
    for match in re.finditer(r"<([^>]+)>", path):
        name = match.group(1)
        # Strip converters like <int:foo> -> foo
        if ":" in name:
            name = name.split(":", 1)[1]
        params.append(name)
    return params

def _build_parameters(path: str):
    parameters = []
    for name in _extract_path_params(path):
        parameters.append({
            "name": name,
            "in": "path",
            "required": True,
            "schema": {"type": "string"}
        })
    return parameters

def _legacy_extract_routes_from_ast(app_path: Path):
    routes = []
    tree = ast.parse(app_path.read_text(encoding="utf-8"))
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                # Handle @app.get("/path"), @app.post("/path"), @app.put("/path")
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if isinstance(decorator.func.value, ast.Name) and decorator.func.value.id == "app":
                        method = decorator.func.attr # "get", "post", "put"
                        if method in {"get", "post", "put", "delete", "patch"}:
                            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                                path = decorator.args[0].value
                                routes.append((path, method.upper(), node.name))
    return routes

class SchemaError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"Malformed schema files: {', '.join(errors)}")
        self.errors = errors

def generate_schema(app_path: Path, schemas_dir: Path, lenient: bool = False):
    if not app_path.exists():
        raise FileNotFoundError("app.py not found")
        
    paths = {}
    routes = extract_routes_from_ast(app_path)
    for path, method, endpoint in routes:
        paths.setdefault(path, {})
        paths[path][method.lower()] = {
            "operationId": endpoint,
            "responses": {
                "200": {"description": "OK"}
            }
        }

    schema = {
        "openapi": "3.1.0",
        "info": {
            "title": "Harpocrates API",
            "version": "1.0.0"
        },
        "paths": paths,
        "components": {
            "schemas": {}
        }
    }

    # Normalize Flask-style path parameters to OpenAPI style and attach
    # path parameter definitions for routes such as /api/lineage/<output_digest>.
    normalized_paths = {}
    for path, methods in paths.items():
        normalized = _normalize_path(path)
        normalized_paths.setdefault(normalized, {})
        parameters = _build_parameters(path)
        for method, operation in methods.items():
            if parameters:
                operation = dict(operation)
                operation["parameters"] = parameters
            normalized_paths[normalized][method] = operation
    schema["paths"] = normalized_paths
    
    # Load canonical schemas safely
    errors = []
    if schemas_dir.is_dir():
        for p in sorted(schemas_dir.glob("*.json")):
            try:
                # Check for oversized/malformed schemas
                if p.stat().st_size > 1024 * 1024:
                    if lenient:
                        continue
                    errors.append(f"{p.name}: file size exceeds 1 MiB limit")
                    continue
                with p.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if not isinstance(data, dict):
                        if not lenient:
                            errors.append(f"{p.name}: root must be a JSON object")
                        continue
                    schema_hash = data.get("schemaHash")
                    if not schema_hash:
                        if not lenient:
                            errors.append(f"{p.name}: missing schemaHash")
                        continue
                    schema["components"]["schemas"][schema_hash] = data
            except (OSError, json.JSONDecodeError) as e:
                if not lenient:
                    errors.append(f"{p.name}: {e}")

    if errors and not lenient:
        raise SchemaError(errors)
                
    return schema

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--app-path", type=Path)
    parser.add_argument("--schemas-dir", type=Path)
    parser.add_argument("--lenient", action="store_true", help="Ignore malformed or oversized schema files")
    args = parser.parse_args()
    
    root = Path(__file__).resolve().parent.parent
    app_path = args.app_path or (root / "backend" / "app.py")
    schemas_dir = args.schemas_dir or (root / "backend" / "schemas")
    
    try:
        schema = generate_schema(app_path, schemas_dir, lenient=args.lenient)
        out_json = json.dumps(schema, indent=2)
    except FileNotFoundError as e:
        print(f"dependency failure: {e}", file=sys.stderr)
        sys.exit(2)
    except SyntaxError as e:
        print(f"malformed input: app.py is not valid Python: {e}", file=sys.stderr)
        sys.exit(3)
    except SchemaError as e:
        print("malformed schema files detected:", file=sys.stderr)
        for err in e.errors:
            print(f"  {err}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"schema generation failed: {e}", file=sys.stderr)
        sys.exit(4)
        
    if args.output:
        args.output.write_text(out_json, encoding="utf-8")
    else:
        print(out_json)

if __name__ == '__main__':
    main()

