from __future__ import annotations

import abc
import ast
import sys
from enum import Enum
from pathlib import Path
from typing import Any
from typing import TypedDict


class FragmentDir(str, Enum):
    main = "main"
    scanner = "scanner"

    def __str__(self) -> str:
        return self.value


def construct_annotation(annotation: str | "ast.expr") -> "ast.expr":
    if isinstance(annotation, str):
        return ast.Name(id=annotation, ctx=ast.Load())
    else:
        return annotation


class Modifier(abc.ABC):
    @abc.abstractmethod
    def modify(self, node: ast.ClassDef) -> ast.ClassDef:
        pass


class Docstring(Modifier):
    """Inserts or modifies the docstring of a class definition."""

    def __init__(self, docstring: str) -> None:
        self.docstring = docstring

    def modify(self, node: ast.ClassDef) -> ast.ClassDef:
        if (  # has docstring
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Str)
        ):
            node.body[0].value.s = self.docstring
        else:  # no docstring
            node.body.insert(
                0,
                ast.Expr(
                    value=ast.Str(
                        s=self.docstring,
                    ),
                ),
            )
        return node


class Annotation(Modifier):
    """Modifies the annotation of a class attribute.

    Does not support adding annotations to attributes with no annotations yet.
    """

    def __init__(self, field: str, annotation: str | "ast.expr") -> None:
        self.field = field
        self.annotation = annotation

    def modify(self, node: ast.ClassDef) -> ast.ClassDef:
        for field in node.body:
            if (
                isinstance(field, ast.AnnAssign)
                and getattr(field.target, "id", None) == self.field
            ):
                field.annotation = construct_annotation(self.annotation)
        return node


class AttrDocstring(Modifier):
    """Inserts a PEP 257 attribute docstring as a string literal after
    the attribute.

    This information is picked up by both mkdocstrings and the VSCode
    Python extension."""

    def __init__(self, attr: str, docstring: str) -> None:
        self.attr = attr
        self.docstring = docstring

    def modify(self, classdef: ast.ClassDef) -> ast.ClassDef:
        # FIXME: won't this just break when we modify while iterating?
        for idx, node in enumerate(classdef.body):
            if not (
                isinstance(node, ast.Assign)
                and getattr(node.targets[0], "id", None) == self.attr
            ):
                continue

            next_idx = idx + 1
            if next_idx >= len(classdef.body) or not isinstance(
                classdef.body[next_idx], ast.Expr
            ):
                classdef.body.insert(
                    next_idx,
                    ast.Expr(value=ast.Constant(s=self.docstring)),
                )
            elif isinstance(classdef.body[next_idx], ast.Expr):
                classdef.body[next_idx].value.s = self.docstring

        return classdef


Unset = object()  # Sentinel value so we can pass None as a default


class Field(Modifier):
    def __init__(
        self,
        name: str,
        annotation: str | "ast.expr",
        default: Any = Unset,
        **field_kwargs: Any,
    ) -> None:
        self.name = name
        self.annotation = annotation
        self.default = default
        self.field_kwargs = field_kwargs

    def modify(self, node: ast.ClassDef) -> ast.ClassDef:
        # TODO: support order of insertion
        # Check if field exists, and replace it if it does
        for i, stmt in enumerate(node.body):
            if (
                isinstance(stmt, ast.AnnAssign)
                and getattr(stmt.target, "id", None) == self.name
            ):
                node.body[i] = self.construct_field()
                break
        else:
            # Otherwise, append it to the end
            node.body.append(self.construct_field())
        return node

    def construct_kwargs(self) -> list[ast.keyword]:
        kwargs = []
        for arg, value in self.field_kwargs.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                kwargs.append(ast.keyword(arg=arg, value=ast.Constant(value=value)))
            elif isinstance(value, ast.keyword):
                kwargs.append(value)
            else:
                raise ValueError(f"Invalid keyword value: {value}")
        return kwargs

    def construct_field(self) -> ast.AnnAssign:
        args = []  # type: list[str | ast.expr]
        if self.default is not Unset:
            if isinstance(self.default, ast.expr):
                args.append(self.default)
            else:
                args.append(ast.Constant(value=self.default))
        value = ast.Call(
            args=args,
            func=ast.Name(
                id="Field",
                ctx=ast.Load(),
            ),
            keywords=self.construct_kwargs(),
        )
        return ast.AnnAssign(
            target=ast.Name(id=self.name, ctx=ast.Store()),
            annotation=construct_annotation(self.annotation),
            value=value,
            simple=1,  # might need to be dynamic
        )


# TODO: sort this list
# Changes to existing definitions (change annotation, etc.) or additions
# that are too minor to create new fragments for.
models: dict[str, dict[str, list[Modifier]]] = {
    FragmentDir.scanner: {
        "HarborVulnerabilityReport": [
            Field(
                "generated_at",
                "Optional[datetime]",
                default=None,
                description="The time the report was generated.",
            ),
            Field(
                "artifact",
                "Optional[Artifact]",
                default=None,
                description="The scanned artifact.",
            ),
            Field(
                "scanner",
                "Optional[Scanner]",
                default=None,
                description="The scanner used to generate the report.",
            ),
            Field(
                "severity",
                "Optional[Severity]",
                default=None,
                description="The overall severity of the vulnerabilities.",
            ),
            Field(
                "vulnerabilities",
                "List[VulnerabilityItem]",
                default_factory=ast.keyword(
                    arg="default_factory", value=ast.Name(id="list")
                ),
                description="The list of vulnerabilities found.",
            ),
        ],
        "VulnerabilityItem": [
            Field(
                "severity",
                "Severity",
                default=ast.Attribute(
                    value=ast.Name(id="Severity", ctx=ast.Load()),
                    attr="unknown",
                    ctx=ast.Load(),
                ),
                description="The severity of the vulnerability.",
                example=ast.keyword(
                    arg="example", value=ast.Name(id="Severity.high.value")
                ),
            ),
        ],
    },
    FragmentDir.main: {
        "ProjectMetadata": [Annotation("retention_id", "Optional[Union[str, int]]")],
        "ExtraAttrs": [Annotation("root", "Optional[Dict[str, Any]]")],
        "Error": [Docstring("Error response from Harbor.")],
        "ScanOverview": [Docstring("Overview of scan results.")],
        "VulnerabilitySummary": [
            Docstring("Summary of vulnerabilities found in a scan.")
        ],
        "CVEAllowlistItem": [Docstring("CVE allowlist item.")],
        "RegistryProviderCredentialPattern": [
            Docstring("Pattern for a registry credential.")
        ],
        "RegistryEndpoint": [Docstring("Registry endpoint configuration.")],
        "FilterStyle": [Docstring("Style of the resource filter.")],
        "ReplicationExecution": [Docstring("The execution of a replication job.")],
        "ReplicationTask": [Docstring("A task that is a part of a replication job.")],
        "RobotCreated": [Docstring("Response for robot account creation.")],
        "RobotSec": [Docstring("Response for robot account secret refresh/update.")],
        "Trigger": [Docstring("Trigger type for a 'scan all' job.")],
        "Stats": [Docstring("Progress of the 'scan all' process.")],
        "RetentionRuleParamMetadata": [Docstring("Parameters for a retention rule.")],
        "RetentionSelectorMetadata": [
            Docstring("Metadata for a retention rule selector.")
        ],
        "Quota": [
            Docstring("Quota object.")
        ],  # not really sure how to succinctly describe this
        "ScannerRegistration": [Docstring("A registered scanner adapter.")],
        "ScannerAdapterMetadata": [Docstring("Metadata for a scanner adapter.")],
        "LdapConf": [Docstring("LDAP configuration properties.")],
        "LdapPingResult": [Docstring("Result of a ping to an LDAP server.")],
        "PayloadFormat": [Docstring("Webhook payload format types.")],
        "WebhookTargetObject": [Docstring("Webhook target")],
        "WebhookPolicy": [Docstring("Webhook policy definition.")],
        "WebhookLastTrigger": [
            Docstring("Last trigger of the webhook and the event type of the trigger.")
        ],
        "WebhookJob": [Docstring("A webhook job.")],
        "Parameter": [Docstring("Parameters for a 'scan all' policy.")],
        "ComponentHealthStatus": [Docstring("Health status of a component.")],
        "Accessory": [Docstring("Accessory of an artifact.")],
        "ScanDataExportRequest": [
            Docstring("Criteria for selecting scan data to export.")
        ],
        "ScanDataExportJob": [Docstring("Metadata for a scan data export job.")],
        "ScanDataExportExecution": [Docstring("Execution of a scan data export job.")],
        "ScanDataExportExecutionList": [
            Docstring("List of executed scan data export jobs.")
        ],
        "SearchRepository": [Docstring("Repository search result.")],
        "WorkerPool": [Docstring("Worker pool for job service.")],
        "Worker": [Docstring("Worker in a pool.")],
        "Action": [
            Docstring("Action to perform. Should be 'stop', 'pause', or 'resume'.")
        ],  # Maybe don't hardcode these values in the docstring?
        "ActionRequest": [Docstring("Request to perform an action.")],
        "JobQueue": [Docstring("Information about a job queue.")],
        "ScheduleTask": [Docstring("Information about a scheduled task.")],
        "SchedulerStatus": [Docstring("Status of the scheduler.")],
        "DangerousCVE": [Docstring("A CVE marked as dangerous.")],
        "DangerousArtifact": [Docstring("An artifact marked as dangerous.")],
        "VulnerabilityItem": [Docstring("Vulnerability found by a scan.")],
        "Errors": [Docstring("Errors that occurred while handling a request.")],
        "NativeReportSummary": [Docstring("Summary of a native scan report.")],
        "CVEAllowlist": [Docstring("CVE allowlist for a system or project.")],
        "RegistryInfo": [
            Docstring("Registry information, including base info and capabilities.")
        ],
        "RegistryProviderEndpointPattern": [
            Docstring("Pattern for a registry provider endpoint.")
        ],
        "RetentionRuleMetadata": [Docstring("Metadata for a tag retention rule.")],
        "SupportedWebhookEventTypes": [
            Docstring("Supported event and notification types for webhooks.")
        ],
        "OverallHealthStatus": [Docstring("Overall health status of the system.")],
        "SecuritySummary": [Docstring("Artifact security summary.")],
        "RegistryProviderInfo": [
            Docstring(
                "Registry provider information, including base info and capabilities."
            )
        ],
        "RobotCreate": [Docstring("Request for robot account creation.")],
        "RetentionMetadata": [Docstring("Metadata for a tag retention rule.")],
        "RetentionPolicy": [Docstring("Retention policy.")],
        "Type": [
            AttrDocstring("none", "Cancel the schedule."),
            AttrDocstring("manual", "Trigger schedule right away."),
            AttrDocstring("schedule", "Trigger based on cron schedule."),
        ],
        "Schedule": [
            Annotation("parameters", "Optional[Dict[str, Any]]"),
        ],
        # "GeneralInfo": [
        #     Field(
        #         "with_chartmuseum",
        #         "Optional[bool]",
        #         None,
        #         description="DEPRECATED: Harbor instance is deployed with nested chartmuseum.",
        #     ),
        # ],
    },
}


def modify_module(tree: ast.Module, fragment_dir: FragmentDir) -> ast.Module:
    for node in ast.walk(tree):
        # Check if the node is a ClassDef and the name is 'Foo'
        if isinstance(node, ast.ClassDef) and node.name in models[fragment_dir]:
            for modifier in models[fragment_dir][node.name]:
                node = modifier.modify(node)
    return tree


# Imports that should be added to every file
ADD_IMPORTS = {}  # type: dict[str, list[str]] # module: list[import_name]


def add_imports(tree: ast.Module) -> ast.Module:
    added = set()  # type: set[str]
    # Attempt to append to existing imports first
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module in ADD_IMPORTS:
                node_names = [node.name for node in node.names]
                for name in ADD_IMPORTS[node.module]:
                    if name not in node_names:
                        node.names.append(ast.alias(name=name, asname=None))
                added.add(node.module)
    # Remaining imports that were not appended to existing imports
    for name in set(ADD_IMPORTS) - added:
        names = [ast.alias(name=name, asname=None) for name in ADD_IMPORTS[name]]
        tree.body.insert(1, ast.ImportFrom(module=name, names=names, level=0))
        # Assume from __future__ is at the top of the file
        # Regardless, we automatically sort imports afterwards anyway
    return tree


def _get_class_base_name(classdef: ast.ClassDef) -> str | None:
    if not classdef.bases:
        return None
    if isinstance(classdef.bases[0], ast.Name):
        return getattr(classdef.bases[0], "id", None)
    elif isinstance(classdef.bases[0], ast.Subscript):
        return getattr(classdef.bases[0].value, "id", None)
    return None


def fix_rootmodel_base(classdef: ast.ClassDef) -> ast.ClassDef:
    # Already has a base that is a RootModel with subscript
    # Not touching this.
    if not classdef.bases or isinstance(classdef.bases[0], ast.Subscript):
        return classdef

    # Find the root field and use its annotation to construct the base
    for node in classdef.body:
        if (
            isinstance(node, ast.AnnAssign)
            and getattr(node.target, "id", None) == "root"
        ):
            classdef.bases = [
                ast.Subscript(
                    slice=node.annotation,
                    value=ast.Name(id="RootModel"),
                )
            ]
            break
    return classdef


def insert_or_update_classdefs(
    tree: ast.Module, classdefs: dict[str, ast.ClassDef]
) -> ast.Module:
    updated = set()

    # Update existing classes
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if node.name in classdefs:
            classdef = classdefs[node.name]
            for class_stmt in classdef.body:
                if not isinstance(class_stmt, ast.Pass):
                    node.body.append(class_stmt)
            updated.add(node.name)
        if _get_class_base_name(node) == "RootModel":
            fix_rootmodel_base(node)

    # Add remaining classdefs (new classes)
    for name in set(classdefs) - updated:
        tree.body.append(classdefs[name])

    return tree


class StatementDict(TypedDict):
    imports: list[ast.Import | ast.ImportFrom]
    stmts: list[ast.stmt]


def insert_statements(tree: ast.Module, statements: StatementDict) -> ast.Module:
    tree.body.extend(statements["stmts"])
    tree.body[1:1] = statements["imports"]
    return tree


def extract_classdefs(fragment_ast: ast.Module) -> dict[str, ast.ClassDef]:
    # TODO: gather imports
    classdefs = {}  # type: dict[str, ast.ClassDef]
    for node in ast.walk(fragment_ast):
        if isinstance(node, ast.ClassDef):
            classdefs[node.name] = node
    return classdefs


def extract_statements(fragment_ast: ast.Module) -> StatementDict:
    stmts = StatementDict(imports=[], stmts=[])
    for node in fragment_ast.body:
        if isinstance(node, (ast.ClassDef, ast.Constant)):
            continue
        elif hasattr(node, "value") and isinstance(node.value, ast.Constant):
            continue
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            stmts["imports"].append(node)
        else:
            stmts["stmts"].append(node)
    return stmts


def add_fragments(tree: ast.Module, directory: Path) -> ast.Module:
    classdefs = {}  # type: dict[str, ast.ClassDef]
    statements = StatementDict(imports=[], stmts=[])
    for file in Path(directory).iterdir():
        if file.suffix == ".py":
            fragment_ast = ast.parse(file.read_text())
            classdefs.update(extract_classdefs(fragment_ast))
            stmts = extract_statements(fragment_ast)
            statements["imports"].extend(stmts["imports"])
            statements["stmts"].extend(stmts["stmts"])
    new_tree = insert_or_update_classdefs(tree, classdefs)
    new_tree = insert_statements(new_tree, statements)
    return new_tree


if __name__ == "__main__":
    basedir = Path(__file__).parent

    if sys.argv[1:]:
        input_filename = Path(sys.argv[1])
    else:
        input_filename = basedir.parent / "_models.py"

    if sys.argv[2:]:
        output_filename = Path(sys.argv[2])
    else:
        output_filename = basedir.parent / "models.py"

    if sys.argv[3:]:
        directory = FragmentDir(sys.argv[3])
    else:
        directory = FragmentDir.main
    fragment_dir = basedir / "fragments" / directory

    print("Input: ", input_filename)
    print("Output: ", output_filename)
    print("Fragment dir: ", fragment_dir)

    with open(input_filename, "r") as f:
        source = f.read()
    tree = ast.parse(source)

    # Modify the AST
    new_tree = modify_module(tree, directory)
    new_tree = add_imports(new_tree)
    new_tree = add_fragments(new_tree, fragment_dir)

    # Generate new source code from the modified AST
    new_source = ast.unparse(new_tree)

    # Write back to the file (or another file)
    with open(output_filename, "w") as f:
        f.write(new_source)
