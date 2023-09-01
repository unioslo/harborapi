from __future__ import annotations

import abc
import ast
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


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
            if isinstance(field, ast.AnnAssign) and field.target.id == self.field:
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
            if not (isinstance(node, ast.Assign) and node.targets[0].id == self.attr):
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
        # for now, we just insert at the end
        node.body.append(self.construct_field())
        return node

    def construct_field(self) -> ast.AnnAssign:
        args = []
        if self.default is not Unset:
            args.append(ast.Constant(value=self.default))
        value = ast.Call(
            args=args,
            func=ast.Name(
                id="Field",
                ctx=ast.Load(),
            ),
            keywords=[
                ast.keyword(arg=arg, value=ast.Constant(value=value))
                for arg, value in self.field_kwargs.items()
            ],
        )
        return ast.AnnAssign(
            target=ast.Name(id=self.name, ctx=ast.Store()),
            annotation=construct_annotation(self.annotation),
            value=value,
            simple=1,  # might need to be dynamic
        )


# Changes to existing definitions (change annotation, etc.) or additions
# that are too minor to create new fragments for.
models = {
    "Artifact": [Annotation("scan_overview", "Optional[NativeReportSummary]")],
    "Error": [Docstring("Error response from Harbor.")],
    "ScanOverview": [Docstring("Overview of scan results.")],
    "VulnerabilitySummary": [Docstring("Summary of vulnerabilities found in a scan.")],
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
    "RetentionSelectorMetadata": [Docstring("Metadata for a retention rule selector.")],
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
    "ScanDataExportRequest": [Docstring("Criteria for selecting scan data to export.")],
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
}


def modify_module(tree: ast.Module) -> ast.Module:
    for node in ast.walk(tree):
        # Check if the node is a ClassDef and the name is 'Foo'
        if isinstance(node, ast.ClassDef) and node.name in models:
            for modifier in models[node.name]:
                node = modifier.modify(node)
    return tree


ADD_IMPORTS = {
    "pydantic": ["root_validator", "BaseModel as PydanticBaseModel"],
    "typing": ["Tuple"],
    ".scanner": ["Severity"],
    "..log": ["logger"],
}


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


def extract_nodes(fragment_ast: ast.Module) -> dict[str, list[ast.stmt]]:
    # TODO: gather imports
    nodes = defaultdict(list)
    for node in ast.walk(fragment_ast):
        if isinstance(node, ast.ClassDef):
            for class_node in node.body:
                nodes[node.name].append(class_node)
    return nodes


def insert_nodes(tree: ast.Module, nodes: dict[str, list[ast.stmt]]) -> ast.Module:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name in nodes:
            node.body.extend(nodes[node.name])
    return tree


def add_fragments(tree: ast.Module) -> ast.Module:
    nodes = {}
    for file in Path(basedir / "fragments").iterdir():
        if file.suffix == ".py":
            fragment_ast = ast.parse(file.read_text())
            nodes.update(extract_nodes(fragment_ast))
    return insert_nodes(tree, nodes)


if __name__ == "__main__":
    basedir = Path(__file__).parent

    if sys.argv[1:]:
        input_filename = sys.argv[1]
    else:
        input_filename = basedir.parent / "_models.py"

    if sys.argv[2:]:
        output_filename = sys.argv[2]
    else:
        output_filename = basedir.parent / "models.py"

    print("Input: ", input_filename)
    print("Output: ", output_filename)

    with open(input_filename, "r") as f:
        source = f.read()
    tree = ast.parse(source)

    # Modify the AST
    new_tree = modify_module(tree)
    new_tree = add_imports(new_tree)
    new_tree = add_fragments(new_tree)

    # Generate new source code from the modified AST
    new_source = ast.unparse(new_tree)

    # Write back to the file (or another file)
    with open(output_filename, "w") as f:
        f.write(new_source)
