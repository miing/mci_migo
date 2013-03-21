import sst.actions


def _assert_full_name_in_account_link(full_name):
    sst.actions.assert_text(_get_my_account_link(), full_name[:40])


def _get_my_account_link():
    return sst.actions.get_element(id='account-link')


def _get_devices_link():
    return sst.actions.get_element(id='devices-link')


def _get_applications_link():
    return sst.actions.get_element(id='applications-link')


def _get_log_out_link():
    return sst.actions.get_element(id='logout-link')


def assert_log_in(full_name):
    _assert_full_name_in_account_link(full_name)
    _get_log_out_link()


def assert_log_out():
    sst.actions.fails(_get_my_account_link)
    sst.actions.fails(_get_log_out_link)


def go_to_account():
    sst.actions.click_link(_get_my_account_link())


def go_to_devices():
    sst.actions.click_link(_get_devices_link())


def go_to_applications():
    sst.actions.click_link(_get_applications_link())


def log_out():
    sst.actions.click_link(_get_log_out_link())
