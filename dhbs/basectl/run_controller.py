import sys
from os_ken.lib import hub
hub.patch(thread=False)

from os_ken import cfg, flags, log
from os_ken.base.app_manager import AppManager
from os_ken.controller import controller


def main():
    cfg.CONF(args=[], project="os_ken", version="4.2.2", default_config_files=[])
    log.init_log()
    apps = ["os_ken.controller.ofp_handler"] + sys.argv[1:]
    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(apps)
    contexts = app_mgr.create_contexts()
    services = [hub.spawn(controller.OpenFlowController())]
    services.extend(app_mgr.instantiate_apps(**contexts))
    try:
        hub.joinall(services)
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()
