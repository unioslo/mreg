from mreg.models import Label

from .tests import MregAPITestCase

class LabelTestCase(MregAPITestCase):
    """"This class defines the test suite for api/labels """
    def setUp(self):
        super().setUp()
        self.assert_post('/api/v1/labels/', {'name':'testlabel','description':'Testing test one two'})

    def test_create_label(self):
        # Create a normal label
        self.assert_post('/api/v1/labels/', {'name':'normal_label','description':'A normal label'})
        # Verify that a description is required
        self.assert_post_and_400('/api/v1/labels/', {'name':'testlabel2'})
        # Verify that spaces in the label name isn't allowed
        self.assert_post_and_400('/api/v1/labels/', {'name':'test label 3', 'description':'A label with spaces'})

    def test_delete_label(self):
        self.assert_delete('/api/v1/labels/testlabel')

    def test_get_labels(self):
        response = self.assert_get('/api/v1/labels/')
        data = response.json()
        self.assertEqual(data['count'], 1)
        self.assertEqual(len(data['results']), 1)
        self.assertEqual(data['results'][0]['name'],'testlabel')
