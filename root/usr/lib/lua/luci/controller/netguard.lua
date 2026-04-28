module("luci.controller.netguard", package.seeall)

function index()
    entry({"admin", "services", "netguard"}, template("netguard/index"), _("NetGuard"), 10)
    entry({"admin", "services", "netguard", "connections"}, template("netguard/connections"), _("Connections"), 20)
    entry({"admin", "services", "netguard", "logs"}, template("netguard/logs"), _("Logs"), 30)
    entry({"admin", "services", "netguard", "settings"}, cbi("netguard/settings"), _("Settings"), 40)
end