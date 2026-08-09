import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_container_image_identity",
    ROOT / "scripts" / "verify_container_image_identity.py",
)
IDENTITY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(IDENTITY)


IMAGE_ID = "sha256:" + "a" * 64
OLD_IMAGE_ID = "sha256:" + "b" * 64
EXPECTED_LABELS = {
    IDENTITY.OCI_VERSION: "dev",
    IDENTITY.OCI_REVISION: "abc1234" + "0" * 33,
    IDENTITY.OCI_CREATED: "2026-08-06T04:37:18Z",
}
VERSION_BODY = "SubConverter-Extended dev-abc1234 backend\n"


def image(labels=None):
    return {"Id": IMAGE_ID, "Config": {"Labels": labels or EXPECTED_LABELS}}


def container(labels=None):
    return {"Image": IMAGE_ID, "Config": {"Labels": labels or EXPECTED_LABELS}}


class ContainerImageIdentityTests(unittest.TestCase):
    def verify(self, container_document=None, image_document=None, body=VERSION_BODY):
        return IDENTITY.verify_documents(
            container=container_document or container(),
            image=image_document or image(),
            version_body=body,
            expected_version="dev",
            expected_revision="abc1234" + "0" * 33,
            expected_build_date="2026-08-06T04:37:18Z",
        )

    def test_fresh_container_matches_image_and_runtime(self):
        result = self.verify()
        self.assertEqual(result["image_id"], IMAGE_ID)
        self.assertEqual(result["revision"], "abc1234" + "0" * 33)

    def test_rejects_incorrect_new_image_label(self):
        labels = dict(EXPECTED_LABELS)
        labels[IDENTITY.OCI_REVISION] = "wrong"
        with self.assertRaisesRegex(IDENTITY.IdentityError, "image label"):
            self.verify(image_document=image(labels))

    def test_rejects_old_container_config_labels_on_new_image(self):
        labels = dict(EXPECTED_LABELS)
        labels[IDENTITY.OCI_VERSION] = "v1.1.28"
        labels[IDENTITY.OCI_REVISION] = "4b0f5c8"
        with self.assertRaisesRegex(IDENTITY.IdentityError, "container label"):
            self.verify(container_document=container(labels))

    def test_rejects_stale_compose_image_label(self):
        labels = dict(EXPECTED_LABELS)
        labels[IDENTITY.COMPOSE_IMAGE] = OLD_IMAGE_ID
        with self.assertRaisesRegex(IDENTITY.IdentityError, "actual image"):
            self.verify(container_document=container(labels))

    def test_rejects_full_revision_as_runtime_build_id(self):
        with self.assertRaisesRegex(IDENTITY.IdentityError, "runtime /version"):
            self.verify(
                body="SubConverter-Extended dev-"
                + "abc1234"
                + "0" * 33
                + " backend\n"
            )


if __name__ == "__main__":
    unittest.main()
