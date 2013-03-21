from mock import Mock

from u1testutils.logging import LogHandlerTestCase


class LogHandlerTestCaseTestCase(LogHandlerTestCase):

    def test_assertLogLevelContains_check_traceback(self):
        mock_record = Mock()
        mock_record.levelname = 'ERROR'
        mock_record.getMessage.return_value = 'some message'
        mock_record.exc_text = 'the exception'

        self.memento_handler.emit(mock_record)

        self.assertLogLevelContains('ERROR', 'some message',
                                    check_traceback=True)

    def test_MementoHandler_check_check_traceback(self):
        mock_record = Mock()
        mock_record.levelname = 'ERROR'
        mock_record.getMessage.return_value = 'some message'
        mock_record.exc_text = 'the exception'

        self.memento_handler.emit(mock_record)

        result = self.memento_handler.check('ERROR', 'some message',
                                            check_traceback=True)
        self.assertTrue(result)
