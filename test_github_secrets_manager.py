import unittest
from unittest.mock import Mock, MagicMock
import importlib
import base64

sm = importlib.import_module("github-secrets-manager")


def github_200():
    return 200, "ABCDEFG"


def github_put_204(body, headers):
    return 204, "Success"


class TestSecretsManager(unittest.TestCase):
    def setUp(self):
        sm.logger = Mock()
        sm.dryrun = False

    def generate_key(self):

        pk = "htwDayWo5EVxRHweGWIUHS2SoWrQWUf5".encode()
        return base64.b64encode(pk).decode()

    def test_is_repo(self):
        self.assertTrue(sm.is_repo("org1/repo1"))

    def test_is_org(self):
        self.assertFalse(sm.is_repo("org1"))

    def test_actions_get_public_key(self):

        test_public_key = {"key": 123, "key_id": "1235"}
        m_repo_action_handle = MagicMock()
        m_repo_action_handle.repos["org1"]["repo1"]["actions"].secrets[
            "public-key"
        ].get.return_value = (200, test_public_key)
        # Repo
        self.assertEqual(
            sm.get_public_key("org1/repo1", m_repo_action_handle, "actions"),
            test_public_key,
        )
        self.assertEqual(sm.public_key_cache["org1/repo1/actions"], test_public_key)

        # Org
        m_org_action_handle = MagicMock()
        m_org_action_handle.orgs["org1"]["actions"].secrets[
            "public-key"
        ].get.return_value = (200, test_public_key)

        self.assertEqual(
            sm.get_public_key("org1", m_org_action_handle, "actions"), test_public_key
        )
        self.assertEqual(sm.public_key_cache["org1/actions"], test_public_key)

    def test_dependabot_get_public_key(self):

        test_public_key = {"key": 123, "key_id": "1235"}

        m_repo_dependabot_handle = MagicMock()
        m_repo_dependabot_handle.repos["org1"]["repo1"]["dependabot"].secrets[
            "public-key"
        ].get.return_value = (200, test_public_key)

        m_org_dependabot_handle = MagicMock()
        m_org_dependabot_handle.orgs["org1"]["dependabot"].secrets[
            "public-key"
        ].get.return_value = (200, test_public_key)

        # Repo
        self.assertEqual(
            sm.get_public_key("org1/repo1", m_repo_dependabot_handle, "dependabot"),
            test_public_key,
        )
        self.assertEqual(sm.public_key_cache["org1/repo1/dependabot"], test_public_key)

        # Org
        self.assertEqual(
            sm.get_public_key("org1", m_org_dependabot_handle, "dependabot"),
            test_public_key,
        )
        self.assertEqual(sm.public_key_cache["org1/dependabot"], test_public_key)

    def test_upsert_secret(self):

        m_repo_action_handle = MagicMock()
        m_repo_action_handle.repos["org2"]["repo2"]["actions"].secrets[
            "secret1"
        ].put.return_value = (204, "ABCDEFG")

        sm.public_key_cache["org2/repo2/actions"] = {
            "key_id": "123",
            "key": self.generate_key(),
        }

        self.assertTrue(
            sm.upsert_secret(
                "org2/repo2", "secret1", "Test Value", m_repo_action_handle, "actions"
            )
        )

    def test_remove_secret(self):

        m_repo_action_handle = MagicMock()
        m_repo_action_handle.repos["org2"]["repo2"]["actions"].secrets[
            "secret1"
        ].get.return_value = (200, "ABCDEFG")
        m_repo_action_handle.repos["org2"]["repo2"]["actions"].secrets[
            "secret1"
        ].delete.return_value = (204, "ABCDEFG")

        sm.public_key_cache["org2/repo2/actions"] = {
            "key_id": "123",
            "key": self.generate_key(),
        }

        self.assertTrue(
            sm.remove_secret("org2/repo2", "secret1", m_repo_action_handle, "actions")
        )

    def test_manage_secret(self):

        secret = {"name": "SECRET3", "value": "dummy", "orgs": ["org2"]}

        sm.public_key_cache["org2/actions"] = {
            "key_id": "123",
            "key": self.generate_key(),
        }
        m_action_handle = MagicMock()
        m_get = Mock(side_effect=github_200())
        m_put = Mock(side_effect=github_put_204)
        m_action_handle.orgs["org2"]["actions"].secrets["SECRET3"].get = m_get
        m_action_handle.orgs["org2"]["actions"].secrets["SECRET3"].put = m_put
        m_action_handle.orgs["org2"]["actions"].secrets[
            "SECRET3"
        ].delete.return_value = (204, "ABCDEFG")

        self.assertEqual(sm.manage_secret(secret, m_action_handle, {}, "actions"), 0)

        print("Finally")
