import unittest
from unittest.mock import patch
from desktop.vault_manager import DesktopVaultManager
from desktop.api_client import SecureVaultApiClient

class TestNoRawPassword(unittest.TestCase):
    @patch("httpx.Client.post")
    @patch("httpx.Client.get")
    def test_unlock_with_master_password_does_not_send_raw_password(self, mock_get, mock_post):
        # Setup mock responses
        mock_get.return_value.json.return_value = {"master_salt": "ZmFrZXNhbHQ="} # fake_salt in base64
        mock_get.return_value.raise_for_status.return_value = None
        
        mock_post.return_value.json.return_value = {
            "access_token": "token",
            "refresh_token": "refresh",
            "device_id": "device",
            "session_id": "session",
            "user_id": "user",
            "device_status": "trusted"
        }
        mock_post.return_value.raise_for_status.return_value = None
        
        # Initialize
        manager = DesktopVaultManager("/tmp/securevault_test_data")
        
        raw_password = "my_super_secret_raw_password"
        manager.unlock_with_master_password("test@example.com", raw_password)
        
        # Verify the raw password is not in any call args
        for call_args in mock_post.call_args_list:
            args, kwargs = call_args
            json_payload = kwargs.get("json", {})
            self.assertNotIn("password", json_payload, "Raw 'password' key found in payload")
            self.assertIn("auth_secret", json_payload, "'auth_secret' not found in payload")
            self.assertNotEqual(json_payload.get("auth_secret"), raw_password, "Raw password sent in auth_secret field")

if __name__ == '__main__':
    unittest.main()
