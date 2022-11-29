from hypothesis import strategies as st

from harborapi.ext.artifact import ArtifactInfo
from harborapi.ext.report import ArtifactReport
from harborapi.models.models import Repository

from .artifact import artifact_strategy, get_hbv_strategy

artifact_info_strategy = st.builds(
    ArtifactInfo,
    artifact=artifact_strategy,
    repository=st.builds(Repository, name=st.text()),
    report=get_hbv_strategy(),
)

artifact_report_strategy = st.builds(
    ArtifactReport,
    artifacts=st.lists(artifact_info_strategy, min_size=1),
)
