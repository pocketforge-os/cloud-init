# Copyright (C) 2026 PocketForge contributors.
#
# This file is part of cloud-init. See LICENSE file for license information.

import logging

from cloudinit.distros import debian

LOG = logging.getLogger(__name__)


class Distro(debian.Distro):
    """PocketForge relies only on its source-owned network configuration."""

    def generate_fallback_config(self):
        LOG.info("PocketForge disables fallback network configuration")
        return None
