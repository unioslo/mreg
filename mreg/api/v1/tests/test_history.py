from unittest import TestCase, mock
from django.core.exceptions import ValidationError
from mreg.api.v1.history import HistoryLog 

class TestHistoryLog(TestCase):

    @mock.patch('django.db.models.Model.full_clean')
    @mock.patch('mreg.api.v1.history.HistoryLog.manipulate_data')
    @mock.patch('mreg.api.v1.history.HistoryLog.get_jsondata')
    def test_save_log_handles_validation_error(self, mock_get_jsondata, mock_manipulate_data, mock_full_clean):
        mock_full_clean.side_effect = ValidationError('Test error')
        mock_get_jsondata.return_value = "json data"
        mock_manipulate_data.return_value = None

        # Mocking Serializer and its Meta
        mock_serializer = mock.Mock()
        mock_meta = mock.Mock()
        mock_meta.model = mock.Mock(__name__='TestModel')
        mock_serializer.Meta = mock_meta
        mock_serializer.data = {'id': 1, 'name': 'Test'}

        data = {'key': 'value'}  

        # Creating HistoryLog instance
        log = HistoryLog()
        log.model = mock_meta.model
        log.foreign_key_name = 'key'
        log.request = mock.Mock(user=mock.Mock())
        log.log_resource = 'test_resource'
        log.m2m_field = 'test_field'
        log.object = mock.Mock(name='TestObject', id=2)

        # Mocking an instance for save_log_m2m_alteration method
        instance = mock.Mock(id=1, name='TestInstance')

        # Mocking a method for save_log_m2m_alteration method
        method = mock.Mock(__name__='TestMethod')

        with self.assertLogs('mreg.history', level='ERROR') as cm:
            log.save_log('test_action', mock_serializer, data)
            log.save_log_m2m_alteration(method, instance)

        self.assertEqual(mock_full_clean.call_count, 2)

        # Assert that the error was logged twice, with tracebacks.
        self.assertTrue(cm.output[0].startswith('ERROR:mreg.history:'))
        self.assertTrue(cm.output[1].startswith('ERROR:mreg.history:'))
