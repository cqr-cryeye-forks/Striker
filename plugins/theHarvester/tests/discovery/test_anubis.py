#!/usr/bin/env python3
# coding=utf-8
import requests
import os
import pytest

from plugins.theHarvester.theHarvester.discovery import anubis
from plugins.theHarvester.theHarvester.lib.core import Core

pytestmark = pytest.mark.asyncio
github_ci = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestAnubis:
    @staticmethod
    def domain() -> str:
        return 'apple.com'

    async def test_api(self):
        base_url = f'https://jldc.me/anubis/subdomains/{TestAnubis.domain()}'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers, verify=False)
        assert request.status_code == 200

    async def test_do_search(self):
        search = anubis.SearchAnubis(word=TestAnubis.domain())
        await search.do_search()
        return await search.get_hostnames()

    async def test_process(self):
        await self.test_do_search()
        assert len(await self.test_do_search()) > 0
