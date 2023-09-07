"""Fragment that adds new properties and methods to the Repository model"""
from __future__ import annotations

from typing import Optional
from typing import Tuple

from ..log import logger


class Repository(BaseModel):
    @property
    def base_name(self) -> str:
        """The repository name without the project name

        Returns
        -------
        Optional[str]
            The basename of the repository name
        """
        s = self.split_name()
        return s[1] if s else ""

    @property
    def project_name(self) -> str:
        """The name of the project that the repository belongs to

        Returns
        -------
        Optional[str]
            The name of the project that the repository belongs to
        """
        s = self.split_name()
        return s[0] if s else ""

    # TODO: cache?
    def split_name(self) -> Optional[Tuple[str, str]]:
        """Split name into tuple of project and repository name

        Returns
        -------
        Optional[Tuple[str, str]]
            Tuple of project name and repo name
        """
        if not self.name:
            return None
        components = self.name.split("/", 1)
        if len(components) != 2:  # no slash in name
            # Shouldn't happen, but we account for it anyway
            logger.warning(
                "Repository name '%s' is not in the format <project>/<repo>", self.name
            )
            return None
        return components[0], components[1]
