#!/usr/bin/env python3
# coding=utf-8
import os

import requests

import pytest

from plugins.theHarvester.theHarvester.discovery import threatminer
from plugins.theHarvester.theHarvester.lib.core import Core

pytestmark = pytest.mark.asyncio
github_ci = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestThreatminer(object):
    @staticmethod
    def domain() -> str:
        return 'target.com'

    async def test_api(self):
        base_url = f'https://api.threatminer.org/v2/domain.php?q={TestThreatminer.domain()}&rt=5'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers, verify=False)
        assert request.status_code == 200

    async def test_search(self):
        search = threatminer.SearchThreatminer(TestThreatminer.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)
        assert isinstance(await search.get_ips(), set)


if __name__ == '__main__':
    pytest.main()
