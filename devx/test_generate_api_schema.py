import sys
import unittest
import tempfile
import json
from pathlib import Path

import generate_api_schema

class GenerateApiSchemaTest(unittest.TestCase):
    def test_generate_schema_positive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("""
from flask import Flask
app = Flask(__name__)
@app.get('/test')
def test_route():
    pass
            """, encoding="utf-8")
            
            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()
            schema_file = schemas_dir / "test.json"
            schema_file.write_text('{"schemaHash": "123", "type": "object"}', encoding="utf-8")
            
            schema = generate_api_schema.generate_schema(app_py, schemas_dir)
            self.assertIn("/test", schema["paths"])
            self.assertIn("get", schema["paths"]["/test"])
            self.assertEqual(schema["paths"]["/test"]["get"]["operationId"], "test_route")
            
            self.assertIn("123", schema["components"]["schemas"])

    def test_missing_app_py(self):
        with self.assertRaises(FileNotFoundError):
            generate_api_schema.generate_schema(Path("/does/not/exist.py"), Path("/does/not/exist/dir"))

    def test_malformed_app_py(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("def class broken syntax", encoding="utf-8")
            with self.assertRaises(SyntaxError):
                generate_api_schema.generate_schema(app_py, Path("/does/not/exist/dir"))
                
    def test_malformed_json_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("app = 1", encoding="utf-8")
            
            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()
            schema_file = schemas_dir / "test.json"
            schema_file.write_text('{invalid json', encoding="utf-8")
            
            # Non-lenient should raise SchemaError
            with self.assertRaises(generate_api_schema.SchemaError) as ctx:
                generate_api_schema.generate_schema(app_py, schemas_dir)
            self.assertTrue(any("test.json" in err for err in ctx.exception.errors))

            # Lenient should ignore malformed
            schema = generate_api_schema.generate_schema(app_py, schemas_dir, lenient=True)
            self.assertNotIn("test", schema["components"]["schemas"])

    def test_oversized_json_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("app = 1", encoding="utf-8")
            
            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()
            schema_file = schemas_dir / "test.json"
            # Oversized file (> 1MB)
            with schema_file.open("wb") as f:
                f.write(b'{"schemaHash": "123"}')
                f.write(b' ' * (1024 * 1024 + 10))
            
            # Non-lenient should raise SchemaError
            with self.assertRaises(generate_api_schema.SchemaError) as ctx:
                generate_api_schema.generate_schema(app_py, schemas_dir)
            self.assertTrue(any("test.json" in err for err in ctx.exception.errors))

            # Lenient should ignore oversized
            schema = generate_api_schema.generate_schema(app_py, schemas_dir, lenient=True)
            self.assertNotIn("123", schema["components"]["schemas"])

    def test_non_object_json_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("app = 1", encoding="utf-8")
            
            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()
            schema_file = schemas_dir / "array.json"
            schema_file.write_text('[1, 2, 3]', encoding="utf-8")
            
            # Non-lenient should raise SchemaError
            with self.assertRaises(generate_api_schema.SchemaError) as ctx:
                generate_api_schema.generate_schema(app_py, schemas_dir)
            self.assertTrue(any("array.json" in err for err in ctx.exception.errors))

            # Lenient should ignore
            schema = generate_api_schema.generate_schema(app_py, schemas_dir, lenient=True)
            self.assertEqual(schema["components"]["schemas"], {})

    def test_missing_schema_hash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("app = 1", encoding="utf-8")
            
            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()
            schema_file = schemas_dir / "missing_hash.json"
            schema_file.write_text('{"type": "object"}', encoding="utf-8")
            
            # Non-lenient should raise SchemaError
            with self.assertRaises(generate_api_schema.SchemaError) as ctx:
                generate_api_schema.generate_schema(app_py, schemas_dir)
            self.assertTrue(any("missing_hash.json" in err for err in ctx.exception.errors))

            # Lenient should ignore
            schema = generate_api_schema.generate_schema(app_py, schemas_dir, lenient=True)
            self.assertEqual(schema["components"]["schemas"], {})

    def test_multiple_schema_errors_collected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("app = 1", encoding="utf-8")
            
            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()
            (schemas_dir / "bad1.json").write_text("{bad", encoding="utf-8")
            (schemas_dir / "bad2.json").write_text("[]", encoding="utf-8")
            (schemas_dir / "bad3.json").write_text("{}", encoding="utf-8")
            
            with self.assertRaises(generate_api_schema.SchemaError) as ctx:
                generate_api_schema.generate_schema(app_py, schemas_dir)
            errors = ctx.exception.errors
            self.assertEqual(len(errors), 3)
            self.assertTrue(any("bad1.json" in err for err in errors))
            self.assertTrue(any("bad2.json" in err for err in errors))
            self.assertTrue(any("bad3.json" in err for err in errors))

if __name__ == '__main__':
    unittest.main()

