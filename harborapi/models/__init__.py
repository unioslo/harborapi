from . import scanner
from .buildhistory import *
from .models import *
from .oidc import *
from .scanner import Artifact as ScanArtifact
from .scanner import Error as ScanError
from .scanner import HarborVulnerabilityReport
from .scanner import Registry as ScanRegistry
from .scanner import Scanner as ScanScanner
from .scanner import ScannerAdapterMetadata as ScanScannerAdapterMetadata
from .scanner import ScannerCapability as ScanScannerCapability
from .scanner import Severity, VulnerabilityItem

# Due to some overlap in the names of the models generated from the two schemas,
# we need to explicitly import the conflicting models from the other schema prefixed
# with 'Scan'.
#
# We cannot just import from scanner.py and shadow the names of the models in models.py,
# because even though their names are the same, some of the models are different
# from each other.
