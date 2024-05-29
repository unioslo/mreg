from .tests import MregAPITestCase


class LabelTestCase(MregAPITestCase):
    """"This class defines the test suite for api/labels """
    def setUp(self):
        super().setUp()
        self.assert_post('/api/v1/labels/', {'name': 'testlabel', 'description': 'Testing test one two'})

    def test_create_label(self):
        # Create a normal label
        self.assert_post('/api/v1/labels/', {'name': 'normal_label', 'description': 'A normal label'})
        # Creating a label with the same name should fail
        self.assert_post_and_409('/api/v1/labels/', {'name': 'normal_label', 'description': 'A normal label redone'})
        # Verify that a description is required
        self.assert_post_and_400('/api/v1/labels/', {'name': 'testlabel2'})
        # Verify that spaces in the label name isn't allowed
        self.assert_post_and_400('/api/v1/labels/', {'name': 'test label 3', 'description': 'A label with spaces'})

    def test_delete_label_by_name(self):
        self.assert_delete('/api/v1/labels/name/testlabel')

    def test_get_labels(self):
        response = self.assert_get('/api/v1/labels/')
        data = response.json()
        self.assertEqual(data['count'], 1)
        self.assertEqual(len(data['results']), 1)
        self.assertEqual(data['results'][0]['name'], 'testlabel')

    def test_delete_label_by_pk(self):
        # find the id of the label
        response = self.assert_get('/api/v1/labels/')
        data = response.json()
        # delete the label by referring to it by id
        self.assert_delete("/api/v1/labels/{}".format(data['results'][0]['id']))

    def test_change_label_name(self):
        self.assert_patch("/api/v1/labels/name/testlabel", {"name": "newname"})
        # read it back and verify that the name changed
        response = self.assert_get('/api/v1/labels/')
        data = response.json()
        self.assertEqual("newname", data['results'][0]['name'])

    def test_label_name_case_insensitive(self):
        """Test that label names are case insensitive."""
        self.assert_post('/api/v1/labels/', {'name': 'case_insensitive', 'description': 'Case insensitive'})
        self.assert_post_and_409('/api/v1/labels/', {'name': 'CASE_INSENSITIVE', 'description': 'Case insensitive'})
        self.assert_get_and_200('/api/v1/labels/name/case_insensitive')
        self.assert_get_and_200('/api/v1/labels/name/CASE_INSENSITIVE')
