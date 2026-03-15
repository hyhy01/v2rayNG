package com.v3.ang.handler

import android.content.Context
import android.text.TextUtils
import android.util.Log
import com.google.gson.JsonArray
import com.v3.ang.AppConfig
import com.v3.ang.dto.ConfigResult
import com.v3.ang.dto.ProfileItem
import com.v3.ang.dto.RulesetItem
import com.v3.ang.dto.V2rayConfig
import com.v3.ang.dto.V2rayConfig.OutboundBean
import com.v3.ang.dto.V2rayConfig.OutboundBean.OutSettingsBean
import com.v3.ang.dto.V2rayConfig.OutboundBean.StreamSettingsBean
import com.v3.ang.dto.V2rayConfig.RoutingBean.RulesBean
import com.v3.ang.enums.EConfigType
import com.v3.ang.enums.NetworkType
import com.v3.ang.extension.isNotNullEmpty
import com.v3.ang.extension.nullIfBlank
import com.v3.ang.fmt.HttpFmt
import com.v3.ang.fmt.Hysteria2Fmt
import com.v3.ang.fmt.ShadowsocksFmt
import com.v3.ang.fmt.SocksFmt
import com.v3.ang.fmt.TrojanFmt
import com.v3.ang.fmt.VlessFmt
import com.v3.ang.fmt.VmessFmt
import com.v3.ang.fmt.WireguardFmt
import com.v3.ang.util.HttpUtil
import com.v3.ang.util.JsonUtil
import com.v3.ang.util.Utils

object V2rayConfigManager {
    private var initConfigCache: String? = null
    private var initConfigCacheWithTun: String? = null

    //region get config function

    /**
     * Retrieves the V2ray configuration for the given GUID.
     *
     * @param context The context of the caller.
     * @param guid The unique identifier for the V2ray configuration.
     * @return A ConfigResult object containing the configuration details or indicating failure.
     */
    fun getV2rayConfig(context: Context, guid: String): ConfigResult {
        try {
            val config = MmkvManager.decodeServerConfig(guid) ?: return ConfigResult(false)
            return if (config.configType == EConfigType.CUSTOM) {
                getV2rayCustomConfig(context, guid, config)
            } else if (config.configType == EConfigType.POLICYGROUP) {
                getV2rayGroupConfig(context, guid, config)
            } else {
                getV2rayNormalConfig(context, guid, config)
            }
        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to get V2ray config", e)
            return ConfigResult(false)
        }
    }

    /**
     * Retrieves the speedtest V2ray configuration for the given GUID.
     *
     * @param context The context of the caller.
     * @param guid The unique identifier for the V2ray configuration.
     * @return A ConfigResult object containing the configuration details or indicating failure.
     */
    fun getV2rayConfig4Speedtest(context: Context, guid: String): ConfigResult {
        try {
            val config = MmkvManager.decodeServerConfig(guid) ?: return ConfigResult(false)
            return if (config.configType == EConfigType.CUSTOM) {
                getV2rayCustomConfig(context, guid, config)
            } else if (config.configType == EConfigType.POLICYGROUP) {
                // The number of policy groups will not be very large, so no special handling is needed.
                getV2rayGroupConfig(context, guid, config)
            } else {
                getV2rayNormalConfig4Speedtest(context, guid, config)
            }
        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to get V2ray config for speedtest", e)
            return ConfigResult(false)
        }
    }

    /**
     * Retrieves the custom V2ray configuration.
     *
     * @param guid The unique identifier for the V2ray configuration.
     * @param config The profile item containing the configuration details.
     * @return A ConfigResult object containing the result of the configuration retrieval.
     */
    private fun getV2rayCustomConfig(context: Context, guid: String, config: ProfileItem): ConfigResult {
        val raw = MmkvManager.decodeServerRaw(guid) ?: return ConfigResult(false)
        val result = ConfigResult(true, guid, raw)
        if (!needTun()) {
            return result
        }

        // check if tun inbound exists
        val json = JsonUtil.parseString(raw) ?: return result
        val inboundsJson = if (json.has("inbounds") && json.get("inbounds")?.isJsonNull == false) {
            json.getAsJsonArray("inbounds")
        } else {
            JsonArray()
        }

        for (i in 0 until inboundsJson.size()) {
            val elem = inboundsJson.get(i)
            if (elem.isJsonObject) {
                val inb = elem.asJsonObject
                val tag = if (inb.has("tag") && inb.get("tag")?.isJsonNull == false) inb.get("tag").asString else ""
                if (tag == "tun") return result
            }
        }

        // add tun inbound from template
        val templateConfig = initV2rayConfig(context) ?: return result
        val inboundTun = templateConfig.inbounds.firstOrNull { it.tag == "tun" } ?: return result
        inboundTun.settings?.mtu = SettingsManager.getVpnMtu()

        // add to json
        inboundsJson.add(JsonUtil.parseString(JsonUtil.toJson(inboundTun)))
        if (inboundsJson.size() == 1) {
            json.add("inbounds", inboundsJson)
        }

        val updatedRaw = JsonUtil.toJsonPretty(json) ?: return result
        return ConfigResult(true, guid, updatedRaw)
    }

    /**
     * Retrieves the group V2ray configuration.
     *
     * @param context The context in which the function is called.
     * @param guid The unique identifier for the V2ray configuration.
     * @param config The profile item containing the configuration details.
     * @return A ConfigResult object containing the result of the configuration retrieval.
     */
    private fun getV2rayGroupConfig(context: Context, guid: String, config: ProfileItem): ConfigResult {
        val result = ConfigResult(false)

        val serverList = MmkvManager.decodeAllServerList()
        val configList = serverList
            .mapNotNull { id -> MmkvManager.decodeServerConfig(id) }
            .filter { profile ->
                val subscriptionId = config.policyGroupSubscriptionId
                if (subscriptionId.isNullOrBlank()) {
                    true
                } else {
                    profile.subscriptionId == subscriptionId
                }
            }
            .filter { profile ->
                val filter = config.policyGroupFilter
                if (filter.isNullOrBlank()) {
                    true
                } else {
                    try {
                        Regex(filter).containsMatchIn(profile.remarks)
                    } catch (e: Exception) {
                        profile.remarks.contains(filter)
                    }
                }
            }

        val v3Config = getV2rayMultipleConfig(context, config, configList) ?: return result

        result.status = true
        result.content = JsonUtil.toJsonPretty(v3Config) ?: ""
        result.guid = guid

        return result
    }

    /**
     * Retrieves the normal V2ray configuration.
     *
     * @param context The context in which the function is called.
     * @param guid The unique identifier for the V2ray configuration.
     * @param config The profile item containing the configuration details.
     * @return A ConfigResult object containing the result of the configuration retrieval.
     */
    private fun getV2rayNormalConfig(context: Context, guid: String, config: ProfileItem): ConfigResult {
        val result = ConfigResult(false)

        val address = config.server ?: return result
        if (!Utils.isPureIpAddress(address)) {
            if (!Utils.isValidUrl(address)) {
                Log.w(AppConfig.TAG, "$address is an invalid ip or domain")
                return result
            }
        }

        val v3Config = initV2rayConfig(context) ?: return result
        v3Config.log.loglevel = MmkvManager.decodeSettingsString(AppConfig.PREF_LOGLEVEL) ?: "warning"
        v3Config.remarks = config.remarks

        getInbounds(v3Config)

        getOutbounds(v3Config, config) ?: return result
        getMoreOutbounds(v3Config, config.subscriptionId)

        getRouting(v3Config)

        getFakeDns(v3Config)

        getDns(v3Config)

        if (MmkvManager.decodeSettingsBool(AppConfig.PREF_LOCAL_DNS_ENABLED) == true) {
            getCustomLocalDns(v3Config)
        }
        if (MmkvManager.decodeSettingsBool(AppConfig.PREF_SPEED_ENABLED) != true) {
            v3Config.stats = null
            v3Config.policy = null
        }

        //Resolve and add to DNS Hosts
        if (MmkvManager.decodeSettingsString(AppConfig.PREF_OUTBOUND_DOMAIN_RESOLVE_METHOD, "1") == "1") {
            resolveOutboundDomainsToHosts(v3Config)
        }

        result.status = true
        result.content = JsonUtil.toJsonPretty(v3Config) ?: ""
        result.guid = guid
        return result
    }

    private fun getV2rayMultipleConfig(context: Context, config: ProfileItem, configList: List<ProfileItem>): V2rayConfig? {
        val validConfigs = configList.asSequence().filter { it.server.isNotNullEmpty() }
            .filter { !Utils.isPureIpAddress(it.server!!) || Utils.isValidUrl(it.server!!) }
            .filter { it.configType != EConfigType.CUSTOM }
            .filter { it.configType != EConfigType.POLICYGROUP }
            .toList()

        if (validConfigs.isEmpty()) {
            Log.w(AppConfig.TAG, "All configs are invalid")
            return null
        }

        val v3Config = initV2rayConfig(context) ?: return null
        v3Config.log.loglevel = MmkvManager.decodeSettingsString(AppConfig.PREF_LOGLEVEL) ?: "warning"
        v3Config.remarks = config.remarks

        getInbounds(v3Config)

        v3Config.outbounds.removeAt(0)
        val outboundsList = mutableListOf<OutboundBean>()
        var index = 0
        for (config in validConfigs) {
            index++
            val outbound = convertProfile2Outbound(config) ?: continue
            val ret = updateOutboundWithGlobalSettings(outbound)
            if (!ret) continue
            outbound.tag = "proxy-$index"
            outboundsList.add(outbound)
        }
        outboundsList.addAll(v3Config.outbounds)
        v3Config.outbounds = ArrayList(outboundsList)

        getRouting(v3Config)

        getFakeDns(v3Config)

        getDns(v3Config)

        getBalance(v3Config, config)

        if (MmkvManager.decodeSettingsBool(AppConfig.PREF_LOCAL_DNS_ENABLED)) {
            getCustomLocalDns(v3Config)
        }
        if (!MmkvManager.decodeSettingsBool(AppConfig.PREF_SPEED_ENABLED)) {
            v3Config.stats = null
            v3Config.policy = null
        }

        //Resolve and add to DNS Hosts
        if (MmkvManager.decodeSettingsString(AppConfig.PREF_OUTBOUND_DOMAIN_RESOLVE_METHOD, "1") == "1") {
            resolveOutboundDomainsToHosts(v3Config)
        }

        return v3Config
    }

    /**
     * Retrieves the normal V2ray configuration for speedtest.
     *
     * @param context The context in which the function is called.
     * @param guid The unique identifier for the V2ray configuration.
     * @param config The profile item containing the configuration details.
     * @return A ConfigResult object containing the result of the configuration retrieval.
     */
    private fun getV2rayNormalConfig4Speedtest(context: Context, guid: String, config: ProfileItem): ConfigResult {
        val result = ConfigResult(false)

        val address = config.server ?: return result
        if (!Utils.isPureIpAddress(address)) {
            if (!Utils.isValidUrl(address)) {
                Log.w(AppConfig.TAG, "$address is an invalid ip or domain")
                return result
            }
        }

        val v3Config = initV2rayConfig(context) ?: return result

        getOutbounds(v3Config, config) ?: return result
        getMoreOutbounds(v3Config, config.subscriptionId)

        v3Config.log.loglevel = MmkvManager.decodeSettingsString(AppConfig.PREF_LOGLEVEL) ?: "warning"
        v3Config.inbounds.clear()
        v3Config.routing.rules.clear()
        v3Config.dns = null
        v3Config.fakedns = null
        v3Config.stats = null
        v3Config.policy = null

        v3Config.outbounds.forEach { key ->
            key.mux = null
        }

        result.status = true
        result.content = JsonUtil.toJsonPretty(v3Config) ?: ""
        result.guid = guid
        return result
    }

    /**
     * Initializes V2ray configuration.
     *
     * This function loads the V2ray configuration from assets or from a cached value.
     * It first attempts to use the cached configuration if available, otherwise reads
     * the configuration from the "v3_config.json" asset file.
     *
     * @param context Android context used to access application assets
     * @return V2rayConfig object parsed from the JSON configuration, or null if the configuration is empty
     */
    private fun initV2rayConfig(context: Context): V2rayConfig? {
        var assets = ""
        if (needTun()) {
            assets = initConfigCacheWithTun ?: Utils.readTextFromAssets(context, "v3_config_with_tun.json")
            if (TextUtils.isEmpty(assets)) {
                return null
            }
            initConfigCacheWithTun = assets
        } else {
            assets = initConfigCache ?: Utils.readTextFromAssets(context, "v3_config.json")
            if (TextUtils.isEmpty(assets)) {
                return null
            }
            initConfigCache = assets
        }
        val config = JsonUtil.fromJson(assets, V2rayConfig::class.java)
        return config
    }


    //endregion


    //region some sub function

    private fun needTun(): Boolean {
        return SettingsManager.isVpnMode() && !SettingsManager.isUsingHevTun()
    }

    /**
     * Configures the inbound settings for V2ray.
     *
     * This function sets up the listening ports, sniffing options, and other inbound-related configurations.
     *
     * @param v3Config The V2ray configuration object to be modified
     * @return true if inbound configuration was successful, false otherwise
     */
    private fun getInbounds(v3Config: V2rayConfig): Boolean {
        try {
            val socksPort = SettingsManager.getSocksPort()
            val inbound1 = v3Config.inbounds[0]

            if (MmkvManager.decodeSettingsBool(AppConfig.PREF_PROXY_SHARING) != true) {
                inbound1.listen = AppConfig.LOOPBACK
            }
            inbound1.port = socksPort
            val fakedns = MmkvManager.decodeSettingsBool(AppConfig.PREF_FAKE_DNS_ENABLED) == true
            val sniffAllTlsAndHttp =
                MmkvManager.decodeSettingsBool(AppConfig.PREF_SNIFFING_ENABLED, true) != false
            inbound1.sniffing?.enabled = fakedns || sniffAllTlsAndHttp
            inbound1.sniffing?.routeOnly =
                MmkvManager.decodeSettingsBool(AppConfig.PREF_ROUTE_ONLY_ENABLED, false)
            if (!sniffAllTlsAndHttp) {
                inbound1.sniffing?.destOverride?.clear()
            }
            if (fakedns) {
                inbound1.sniffing?.destOverride?.add("fakedns")
            }

            if (!Utils.isXray()) {
                val inbound2 = JsonUtil.fromJson(JsonUtil.toJson(inbound1), V2rayConfig.InboundBean::class.java) ?: return false
                inbound2.tag = EConfigType.HTTP.name.lowercase()
                inbound2.port = SettingsManager.getHttpPort()
                inbound2.protocol = EConfigType.HTTP.name.lowercase()
                v3Config.inbounds.add(inbound2)
            }

            if (needTun()) {
                val inboundTun = v3Config.inbounds.firstOrNull { e -> e.tag == "tun" }
                inboundTun?.settings?.mtu = SettingsManager.getVpnMtu()
                inboundTun?.sniffing = inbound1.sniffing
            }
        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to configure inbounds", e)
            return false
        }
        return true
    }

    /**
     * Configures the fake DNS settings if enabled.
     *
     * Adds FakeDNS configuration to v3Config if both local DNS and fake DNS are enabled.
     *
     * @param v3Config The V2ray configuration object to be modified
     */
    private fun getFakeDns(v3Config: V2rayConfig) {
        if (MmkvManager.decodeSettingsBool(AppConfig.PREF_LOCAL_DNS_ENABLED) == true
            && MmkvManager.decodeSettingsBool(AppConfig.PREF_FAKE_DNS_ENABLED) == true
        ) {
            v3Config.fakedns = listOf(V2rayConfig.FakednsBean())
        }
    }

    /**
     * Configures routing settings for V2ray.
     *
     * Sets up the domain strategy and adds routing rules from saved rulesets.
     *
     * @param v3Config The V2ray configuration object to be modified
     * @return true if routing configuration was successful, false otherwise
     */
    private fun getRouting(v3Config: V2rayConfig): Boolean {
        try {

            v3Config.routing.domainStrategy =
                MmkvManager.decodeSettingsString(AppConfig.PREF_ROUTING_DOMAIN_STRATEGY)
                    ?: "AsIs"

            val rulesetItems = MmkvManager.decodeRoutingRulesets()
            rulesetItems?.forEach { key ->
                getRoutingUserRule(key, v3Config)
            }
        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to configure routing", e)
            return false
        }
        return true
    }

    /**
     * Adds a specific ruleset item to the routing configuration.
     *
     * @param item The ruleset item to add
     * @param v3Config The V2ray configuration object to be modified
     */
    private fun getRoutingUserRule(item: RulesetItem?, v3Config: V2rayConfig) {
        try {
            if (item == null || !item.enabled) {
                return
            }

            val rule = JsonUtil.fromJson(JsonUtil.toJson(item), RulesBean::class.java) ?: return

            // Replace specific geoip rules with ext versions
            rule.ip?.let { ipList ->
                val updatedIpList = ArrayList<String>()
                ipList.forEach { ip ->
                    when (ip) {
                        AppConfig.GEOIP_CN -> updatedIpList.add("ext:${AppConfig.GEOIP_ONLY_CN_PRIVATE_DAT}:cn")
                        AppConfig.GEOIP_PRIVATE -> updatedIpList.add("ext:${AppConfig.GEOIP_ONLY_CN_PRIVATE_DAT}:private")
                        else -> updatedIpList.add(ip)
                    }
                }
                rule.ip = updatedIpList
            }

            v3Config.routing.rules.add(rule)

        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to apply routing user rule", e)
        }
    }

    /**
     * Retrieves domain rules for a specific outbound tag.
     *
     * Searches through all rulesets to find domains targeting the specified tag.
     *
     * @param tag The outbound tag to search for
     * @return ArrayList of domain rules matching the tag
     */
    private fun getUserRule2Domain(tag: String): ArrayList<String> {
        val domain = ArrayList<String>()

        val rulesetItems = MmkvManager.decodeRoutingRulesets()
        rulesetItems?.forEach { key ->
            if (key.enabled && key.outboundTag == tag && !key.domain.isNullOrEmpty()) {
                key.domain?.forEach {
                    if (it != AppConfig.GEOSITE_PRIVATE
                        && (it.startsWith("geosite:") || it.startsWith("domain:"))
                    ) {
                        domain.add(it)
                    }
                }
            }
        }

        return domain
    }

    /**
     * Configures custom local DNS settings.
     *
     * Sets up DNS inbound, outbound, and routing rules for local DNS resolution.
     *
     * @param v3Config The V2ray configuration object to be modified
     * @return true if custom local DNS configuration was successful, false otherwise
     */
    private fun getCustomLocalDns(v3Config: V2rayConfig): Boolean {
        try {
            if (MmkvManager.decodeSettingsBool(AppConfig.PREF_FAKE_DNS_ENABLED) == true) {
                val geositeCn = arrayListOf(AppConfig.GEOSITE_CN)
                val proxyDomain = getUserRule2Domain(AppConfig.TAG_PROXY)
                val directDomain = getUserRule2Domain(AppConfig.TAG_DIRECT)
                // fakedns with all domains to make it always top priority
                v3Config.dns?.servers?.add(
                    0,
                    V2rayConfig.DnsBean.ServersBean(
                        address = "fakedns",
                        domains = geositeCn.plus(proxyDomain).plus(directDomain)
                    )
                )
            }

            if(SettingsManager.isVpnMode()) {
                if (SettingsManager.isUsingHevTun()) {
                    //hev-socks5-tunnel dns routing
                    v3Config.routing.rules.add(
                        0, RulesBean(
                            inboundTag = arrayListOf("socks"),
                            outboundTag = "dns-out",
                            port = "53",
                        )
                    )
                } else {
                    v3Config.routing.rules.add(
                        0, RulesBean(
                            inboundTag = arrayListOf("tun"),
                            outboundTag = "dns-out",
                            port = "53",
                        )
                    )
                }
            }

            // DNS outbound
            if (v3Config.outbounds.none { e -> e.protocol == "dns" && e.tag == "dns-out" }) {
                v3Config.outbounds.add(
                    OutboundBean(
                        protocol = "dns",
                        tag = "dns-out",
                        settings = null,
                        streamSettings = null,
                        mux = null
                    )
                )
            }
        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to configure custom local DNS", e)
            return false
        }
        return true
    }

    /**
     * Configures the DNS settings for V2ray.
     *
     * Sets up DNS servers, hosts, and routing rules for DNS resolution.
     *
     * @param v3Config The V2ray configuration object to be modified
     * @return true if DNS configuration was successful, false otherwise
     */
    private fun getDns(v3Config: V2rayConfig): Boolean {
        try {
            val hosts = mutableMapOf<String, Any>()
            val servers = ArrayList<Any>()

            //remote Dns
            val remoteDns = SettingsManager.getRemoteDnsServers()
            val proxyDomain = getUserRule2Domain(AppConfig.TAG_PROXY)
            remoteDns.forEach {
                servers.add(it)
            }
            if (proxyDomain.isNotEmpty()) {
                servers.add(
                    V2rayConfig.DnsBean.ServersBean(
                        address = remoteDns.first(),
                        domains = proxyDomain,
                    )
                )
            }

            // domestic DNS
            val domesticDns = SettingsManager.getDomesticDnsServers()
            val directDomain = getUserRule2Domain(AppConfig.TAG_DIRECT)
            val isCnRoutingMode = directDomain.contains(AppConfig.GEOSITE_CN)
            val geoipCn = arrayListOf(AppConfig.GEOIP_CN)
            if (directDomain.isNotEmpty()) {
                servers.add(
                    V2rayConfig.DnsBean.ServersBean(
                        address = domesticDns.first(),
                        domains = directDomain,
                        expectIPs = if (isCnRoutingMode) geoipCn else null,
                        skipFallback = true,
                        tag = AppConfig.TAG_DOMESTIC_DNS
                    )
                )
            }

            //block dns
            val blkDomain = getUserRule2Domain(AppConfig.TAG_BLOCKED)
            if (blkDomain.isNotEmpty()) {
                hosts.putAll(blkDomain.map { it to AppConfig.LOOPBACK })
            }

            // hardcode googleapi rule to fix play store problems
            hosts[AppConfig.GOOGLEAPIS_CN_DOMAIN] = AppConfig.GOOGLEAPIS_COM_DOMAIN

            // hardcode popular Android Private DNS rule to fix localhost DNS problem
            hosts[AppConfig.DNS_ALIDNS_DOMAIN] = AppConfig.DNS_ALIDNS_ADDRESSES
            hosts[AppConfig.DNS_CLOUDFLARE_ONE_DOMAIN] = AppConfig.DNS_CLOUDFLARE_ONE_ADDRESSES
            hosts[AppConfig.DNS_CLOUDFLARE_DNS_COM_DOMAIN] = AppConfig.DNS_CLOUDFLARE_DNS_COM_ADDRESSES
            hosts[AppConfig.DNS_CLOUDFLARE_DNS_DOMAIN] = AppConfig.DNS_CLOUDFLARE_DNS_ADDRESSES
            hosts[AppConfig.DNS_DNSPOD_DOMAIN] = AppConfig.DNS_DNSPOD_ADDRESSES
            hosts[AppConfig.DNS_GOOGLE_DOMAIN] = AppConfig.DNS_GOOGLE_ADDRESSES
            hosts[AppConfig.DNS_QUAD9_DOMAIN] = AppConfig.DNS_QUAD9_ADDRESSES
            hosts[AppConfig.DNS_YANDEX_DOMAIN] = AppConfig.DNS_YANDEX_ADDRESSES

            //User DNS hosts
            try {
                val userHosts = MmkvManager.decodeSettingsString(AppConfig.PREF_DNS_HOSTS)
                if (userHosts.isNotNullEmpty()) {
                    var userHostsMap = userHosts?.split(",")
                        ?.filter { it.isNotEmpty() }
                        ?.filter { it.contains(":") }
                        ?.associate { it.split(":").let { (k, v) -> k to v } }
                    if (userHostsMap != null) hosts.putAll(userHostsMap)
                }
            } catch (e: Exception) {
                Log.e(AppConfig.TAG, "Failed to configure user DNS hosts", e)
            }

            // DNS dns
            v3Config.dns = V2rayConfig.DnsBean(
                servers = servers,
                hosts = hosts,
                tag = AppConfig.TAG_DNS
            )

            // DNS routing
            v3Config.routing.rules.add(
                RulesBean(
                    outboundTag = AppConfig.TAG_DIRECT,
                    inboundTag = arrayListOf(AppConfig.TAG_DOMESTIC_DNS),
                    domain = null
                )
            )
            v3Config.routing.rules.add(
                RulesBean(
                    outboundTag = AppConfig.TAG_PROXY,
                    inboundTag = arrayListOf(AppConfig.TAG_DNS),
                    domain = null
                )
            )
        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to configure DNS", e)
            return false
        }
        return true
    }


    //endregion


    //region outbound related functions

    /**
     * Configures the primary outbound connection.
     *
     * Converts the profile to an outbound configuration and applies global settings.
     *
     * @param v3Config The V2ray configuration object to be modified
     * @param config The profile item containing connection details
     * @return true if outbound configuration was successful, null if there was an error
     */
    private fun getOutbounds(v3Config: V2rayConfig, config: ProfileItem): Boolean? {
        val outbound = convertProfile2Outbound(config) ?: return null
        val ret = updateOutboundWithGlobalSettings(outbound)
        if (!ret) return null

        if (v3Config.outbounds.isNotEmpty()) {
            v3Config.outbounds[0] = outbound
        } else {
            v3Config.outbounds.add(outbound)
        }

        updateOutboundFragment(v3Config)
        return true
    }

    /**
     * Configures additional outbound connections for proxy chaining.
     *
     * Sets up previous and next proxies in a subscription for advanced routing capabilities.
     *
     * @param v3Config The V2ray configuration object to be modified
     * @param subscriptionId The subscription ID to look up related proxies
     * @return true if additional outbounds were configured successfully, false otherwise
     */
    private fun getMoreOutbounds(v3Config: V2rayConfig, subscriptionId: String): Boolean {
        //fragment proxy
        if (MmkvManager.decodeSettingsBool(AppConfig.PREF_FRAGMENT_ENABLED, false) == true) {
            return false
        }

        if (subscriptionId.isEmpty()) {
            return false
        }
        try {
            val subItem = MmkvManager.decodeSubscription(subscriptionId) ?: return false

            //current proxy
            val outbound = v3Config.outbounds[0]

            //Previous proxy
            val prevNode = SettingsManager.getServerViaRemarks(subItem.prevProfile)
            if (prevNode != null) {
                val prevOutbound = convertProfile2Outbound(prevNode)
                if (prevOutbound != null) {
                    updateOutboundWithGlobalSettings(prevOutbound)
                    prevOutbound.tag = AppConfig.TAG_PROXY + "2"
                    v3Config.outbounds.add(prevOutbound)
                    outbound.ensureSockopt().dialerProxy = prevOutbound.tag
                }
            }

            //Next proxy
            val nextNode = SettingsManager.getServerViaRemarks(subItem.nextProfile)
            if (nextNode != null) {
                val nextOutbound = convertProfile2Outbound(nextNode)
                if (nextOutbound != null) {
                    updateOutboundWithGlobalSettings(nextOutbound)
                    nextOutbound.tag = AppConfig.TAG_PROXY
                    v3Config.outbounds.add(0, nextOutbound)
                    outbound.tag = AppConfig.TAG_PROXY + "1"
                    nextOutbound.ensureSockopt().dialerProxy = outbound.tag
                }
            }
        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to configure more outbounds", e)
            return false
        }

        return true
    }

    /**
     * Updates outbound settings based on global preferences.
     *
     * Applies multiplexing and protocol-specific settings to an outbound connection.
     *
     * @param outbound The outbound connection to update
     * @return true if the update was successful, false otherwise
     */
    private fun updateOutboundWithGlobalSettings(outbound: OutboundBean): Boolean {
        try {
            var muxEnabled = MmkvManager.decodeSettingsBool(AppConfig.PREF_MUX_ENABLED, false)
            val protocol = outbound.protocol
            if (protocol.equals(EConfigType.SHADOWSOCKS.name, true)
                || protocol.equals(EConfigType.SOCKS.name, true)
                || protocol.equals(EConfigType.HTTP.name, true)
                || protocol.equals(EConfigType.TROJAN.name, true)
                || protocol.equals(EConfigType.WIREGUARD.name, true)
                || protocol.equals(EConfigType.HYSTERIA2.name, true)
                || protocol.equals(EConfigType.HYSTERIA.name, true)
            ) {
                muxEnabled = false
            } else if (outbound.streamSettings?.network == NetworkType.XHTTP.type) {
                muxEnabled = false
            }

            if (muxEnabled) {
                outbound.mux?.enabled = true
                outbound.mux?.concurrency = MmkvManager.decodeSettingsString(AppConfig.PREF_MUX_CONCURRENCY, "8").orEmpty().toInt()
                outbound.mux?.xudpConcurrency = MmkvManager.decodeSettingsString(AppConfig.PREF_MUX_XUDP_CONCURRENCY, "16").orEmpty().toInt()
                outbound.mux?.xudpProxyUDP443 = MmkvManager.decodeSettingsString(AppConfig.PREF_MUX_XUDP_QUIC, "reject")
                if (protocol.equals(EConfigType.VLESS.name, true) && outbound.settings?.vnext?.first()?.users?.first()?.flow?.isNotEmpty() == true) {
                    outbound.mux?.concurrency = -1
                }
            } else {
                outbound.mux?.enabled = false
                outbound.mux?.concurrency = -1
            }

            if (protocol.equals(EConfigType.WIREGUARD.name, true)) {
                var localTunAddr = if (outbound.settings?.address == null) {
                    listOf(AppConfig.WIREGUARD_LOCAL_ADDRESS_V4)
                } else {
                    outbound.settings?.address as List<*>
                }
                if (MmkvManager.decodeSettingsBool(AppConfig.PREF_PREFER_IPV6) != true) {
                    localTunAddr = listOf(localTunAddr.first())
                }
                outbound.settings?.address = localTunAddr
            }

            if (outbound.streamSettings?.network == AppConfig.DEFAULT_NETWORK
                && outbound.streamSettings?.tcpSettings?.header?.type == AppConfig.HEADER_TYPE_HTTP
            ) {
                val path = outbound.streamSettings?.tcpSettings?.header?.request?.path
                val host = outbound.streamSettings?.tcpSettings?.header?.request?.headers?.Host

                val requestString: String by lazy {
                    """{"version":"1.1","method":"GET","headers":{"User-Agent":["Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36"],"Accept-Encoding":["gzip, deflate"],"Connection":["keep-alive"],"Pragma":"no-cache"}}"""
                }
                outbound.streamSettings?.tcpSettings?.header?.request = JsonUtil.fromJson(
                    requestString,
                    StreamSettingsBean.TcpSettingsBean.HeaderBean.RequestBean::class.java
                )
                outbound.streamSettings?.tcpSettings?.header?.request?.path =
                    if (path.isNullOrEmpty()) {
                        listOf("/")
                    } else {
                        path
                    }
                outbound.streamSettings?.tcpSettings?.header?.request?.headers?.Host = host
            }


        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to update outbound with global settings", e)
            return false
        }
        return true
    }

    /**
     * Configures load balancing settings for the V2ray configuration.
     *
     * @param v3Config The V2ray configuration object to be modified with balancing settings
     * @param config The profile item containing policy group settings
     */
    private fun getBalance(v3Config: V2rayConfig, config: ProfileItem) {
        try {
            v3Config.routing.rules.forEach { rule ->
                if (rule.outboundTag == "proxy") {
                    rule.outboundTag = null
                    rule.balancerTag = AppConfig.TAG_BALANCER
                }
            }

            val lstSelector =  listOf("proxy-")
            when (config.policyGroupType) {
                // Least Ping goto else
                "1" -> {
                    // Least Load
                    val balancer = V2rayConfig.RoutingBean.BalancerBean(
                        tag = AppConfig.TAG_BALANCER,
                        selector = lstSelector,
                        strategy = V2rayConfig.RoutingBean.StrategyObject(
                            type = "leastLoad"
                        )
                    )
                    v3Config.routing.balancers = listOf(balancer)
                    v3Config.burstObservatory = V2rayConfig.BurstObservatoryObject(
                        subjectSelector = lstSelector,
                        pingConfig = V2rayConfig.BurstObservatoryObject.PingConfigObject(
                            destination = MmkvManager.decodeSettingsString(AppConfig.PREF_DELAY_TEST_URL) ?: AppConfig.DELAY_TEST_URL,
                            interval = "5m",
                            sampling = 2,
                            timeout = "30s"
                        )
                    )
                }
                "2" -> {
                    // Random
                    val balancer = V2rayConfig.RoutingBean.BalancerBean(
                        tag = AppConfig.TAG_BALANCER,
                        selector = lstSelector,
                        strategy = V2rayConfig.RoutingBean.StrategyObject(
                            type = "random"
                        )
                    )
                    v3Config.routing.balancers = listOf(balancer)
                }
                "3" -> {
                    // Round Robin
                    val balancer = V2rayConfig.RoutingBean.BalancerBean(
                        tag = AppConfig.TAG_BALANCER,
                        selector = lstSelector,
                        strategy = V2rayConfig.RoutingBean.StrategyObject(
                            type = "roundRobin"
                        )
                    )
                    v3Config.routing.balancers = listOf(balancer)
                }
                else -> {
                    // Default: Least Ping
                    val balancer = V2rayConfig.RoutingBean.BalancerBean(
                        tag = AppConfig.TAG_BALANCER,
                        selector = lstSelector,
                        strategy = V2rayConfig.RoutingBean.StrategyObject(
                            type = "leastPing"
                        )
                    )
                    v3Config.routing.balancers = listOf(balancer)
                    v3Config.observatory = V2rayConfig.ObservatoryObject(
                        subjectSelector = lstSelector,
                        probeUrl = MmkvManager.decodeSettingsString(AppConfig.PREF_DELAY_TEST_URL) ?: AppConfig.DELAY_TEST_URL,
                        probeInterval = "3m",
                        enableConcurrency = true
                    )
                }
            }

            if (v3Config.routing.domainStrategy == "IPIfNonMatch") {
                v3Config.routing.rules.add(
                    RulesBean(
                        ip = arrayListOf("0.0.0.0/0", "::/0"),
                        balancerTag = AppConfig.TAG_BALANCER,
                    )
                )
            } else {
                v3Config.routing.rules.add(
                    RulesBean(
                        network = "tcp,udp",
                        balancerTag = AppConfig.TAG_BALANCER,
                    )
                )
            }
        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to configure balance", e)
        }
    }

    /**
     * Updates the outbound with fragment settings for traffic optimization.
     *
     * Configures packet fragmentation for TLS and REALITY protocols if enabled.
     *
     * @param v3Config The V2ray configuration object to be modified
     * @return true if fragment configuration was successful, false otherwise
     */
    private fun updateOutboundFragment(v3Config: V2rayConfig): Boolean {
        try {
            if (MmkvManager.decodeSettingsBool(AppConfig.PREF_FRAGMENT_ENABLED, false) == false) {
                return true
            }
            if (v3Config.outbounds[0].streamSettings?.security != AppConfig.TLS
                && v3Config.outbounds[0].streamSettings?.security != AppConfig.REALITY
            ) {
                return true
            }

            val fragmentOutbound =
                OutboundBean(
                    protocol = AppConfig.PROTOCOL_FREEDOM,
                    tag = AppConfig.TAG_FRAGMENT,
                    mux = null
                )

            var packets =
                MmkvManager.decodeSettingsString(AppConfig.PREF_FRAGMENT_PACKETS) ?: "tlshello"
            if (v3Config.outbounds[0].streamSettings?.security == AppConfig.REALITY
                && packets == "tlshello"
            ) {
                packets = "1-3"
            } else if (v3Config.outbounds[0].streamSettings?.security == AppConfig.TLS
                && packets != "tlshello"
            ) {
                packets = "tlshello"
            }

            fragmentOutbound.settings = OutSettingsBean(
                fragment = OutSettingsBean.FragmentBean(
                    packets = packets,
                    length = MmkvManager.decodeSettingsString(AppConfig.PREF_FRAGMENT_LENGTH)
                        ?: "50-100",
                    interval = MmkvManager.decodeSettingsString(AppConfig.PREF_FRAGMENT_INTERVAL)
                        ?: "10-20"
                ),
                noises = listOf(
                    OutSettingsBean.NoiseBean(
                        type = "rand",
                        packet = "10-20",
                        delay = "10-16",
                    )
                ),
            )
            fragmentOutbound.streamSettings = StreamSettingsBean(
                sockopt = StreamSettingsBean.SockoptBean(
                    TcpNoDelay = true,
                    mark = 255
                )
            )
            v3Config.outbounds.add(fragmentOutbound)

            //proxy chain
            v3Config.outbounds[0].streamSettings?.sockopt =
                StreamSettingsBean.SockoptBean(
                    dialerProxy = AppConfig.TAG_FRAGMENT
                )
        } catch (e: Exception) {
            Log.e(AppConfig.TAG, "Failed to update outbound fragment", e)
            return false
        }
        return true
    }

    /**
     * Resolves domain names to IP addresses in outbound connections.
     *
     * Pre-resolves domains to improve connection speed and reliability.
     *
     * @param v3Config The V2ray configuration object to be modified
     */
    private fun resolveOutboundDomainsToHosts(v3Config: V2rayConfig) {
        val proxyOutboundList = v3Config.getAllProxyOutbound()
        val dns = v3Config.dns ?: return
        val newHosts = dns.hosts?.toMutableMap() ?: mutableMapOf()
        val preferIpv6 = MmkvManager.decodeSettingsBool(AppConfig.PREF_PREFER_IPV6) == true

        for (item in proxyOutboundList) {
            val domain = item.getServerAddress()
            if (domain.isNullOrEmpty()) continue

            if (newHosts.containsKey(domain)) {
                item.ensureSockopt().domainStrategy = "UseIP"
                item.ensureSockopt().happyEyeballs = StreamSettingsBean.HappyEyeballsBean(
                    prioritizeIPv6 = preferIpv6,
                    interleave = 2
                )
                continue
            }

            val resolvedIps = HttpUtil.resolveHostToIP(domain, preferIpv6)
            if (resolvedIps.isNullOrEmpty()) continue

            item.ensureSockopt().domainStrategy = "UseIP"
            item.ensureSockopt().happyEyeballs = StreamSettingsBean.HappyEyeballsBean(
                prioritizeIPv6 = preferIpv6,
                interleave = 2
            )
            newHosts[domain] = if (resolvedIps.size == 1) {
                resolvedIps[0]
            } else {
                resolvedIps
            }
        }

        dns.hosts = newHosts
    }

    /**
     * Converts a profile item to an outbound configuration.
     *
     * Creates appropriate outbound settings based on the protocol type.
     *
     * @param profileItem The profile item to convert
     * @return OutboundBean configuration for the profile, or null if not supported
     */
    private fun convertProfile2Outbound(profileItem: ProfileItem): OutboundBean? {
        return when (profileItem.configType) {
            EConfigType.VMESS -> VmessFmt.toOutbound(profileItem)
            EConfigType.CUSTOM -> null
            EConfigType.SHADOWSOCKS -> ShadowsocksFmt.toOutbound(profileItem)
            EConfigType.SOCKS -> SocksFmt.toOutbound(profileItem)
            EConfigType.VLESS -> VlessFmt.toOutbound(profileItem)
            EConfigType.TROJAN -> TrojanFmt.toOutbound(profileItem)
            EConfigType.WIREGUARD -> WireguardFmt.toOutbound(profileItem)
            EConfigType.HYSTERIA2 -> Hysteria2Fmt.toOutbound(profileItem)
            EConfigType.HTTP -> HttpFmt.toOutbound(profileItem)
            EConfigType.POLICYGROUP -> null
            else -> null
        }
    }

    /**
     * Creates an initial outbound configuration for a specific protocol type.
     *
     * Provides a template configuration for different protocol types.
     *
     * @param configType The type of configuration to create
     * @return An initial OutboundBean for the specified configuration type, or null for custom types
     */
    fun createInitOutbound(configType: EConfigType): OutboundBean? {
        return when (configType) {
            EConfigType.VMESS,
            EConfigType.VLESS ->
                return OutboundBean(
                    protocol = configType.name.lowercase(),
                    settings = OutSettingsBean(
                        vnext = listOf(
                            OutSettingsBean.VnextBean(
                                users = listOf(OutSettingsBean.VnextBean.UsersBean())
                            )
                        )
                    ),
                    streamSettings = StreamSettingsBean()
                )

            EConfigType.SHADOWSOCKS,
            EConfigType.SOCKS,
            EConfigType.HTTP,
            EConfigType.TROJAN ->
                return OutboundBean(
                    protocol = configType.name.lowercase(),
                    settings = OutSettingsBean(
                        servers = listOf(OutSettingsBean.ServersBean())
                    ),
                    streamSettings = StreamSettingsBean()
                )

            EConfigType.WIREGUARD ->
                return OutboundBean(
                    protocol = configType.name.lowercase(),
                    settings = OutSettingsBean(
                        secretKey = "",
                        peers = listOf(OutSettingsBean.WireGuardBean())
                    )
                )

            EConfigType.HYSTERIA,
            EConfigType.HYSTERIA2 ->
                return OutboundBean(
                    protocol = EConfigType.HYSTERIA.name.lowercase(),
                    settings = OutSettingsBean(
                        servers = null
                    ),
                    streamSettings = StreamSettingsBean()
                )

            EConfigType.CUSTOM -> null
            EConfigType.POLICYGROUP -> null
        }
    }

    /**
     * Configures transport settings for an outbound connection.
     *
     * Sets up protocol-specific transport options based on the profile settings.
     *
     * @param streamSettings The stream settings to configure
     * @param profileItem The profile containing transport configuration
     * @return The Server Name Indication (SNI) value to use, or null if not applicable
     */
    fun populateTransportSettings(streamSettings: StreamSettingsBean, profileItem: ProfileItem): String? {
        val transport = profileItem.network.orEmpty()
        val headerType = profileItem.headerType
        val host = profileItem.host
        val path = profileItem.path
        val seed = profileItem.seed
//        val quicSecurity = profileItem.quicSecurity
//        val key = profileItem.quicKey
        val mode = profileItem.mode
        val serviceName = profileItem.serviceName
        val authority = profileItem.authority
        val xhttpMode = profileItem.xhttpMode
        val xhttpExtra = profileItem.xhttpExtra

        var sni: String? = null
        streamSettings.network = transport.ifEmpty { NetworkType.TCP.type }
        when (streamSettings.network) {
            NetworkType.TCP.type -> {
                val tcpSetting = StreamSettingsBean.TcpSettingsBean()
                if (headerType == AppConfig.HEADER_TYPE_HTTP) {
                    tcpSetting.header.type = AppConfig.HEADER_TYPE_HTTP
                    if (!TextUtils.isEmpty(host) || !TextUtils.isEmpty(path)) {
                        val requestObj = StreamSettingsBean.TcpSettingsBean.HeaderBean.RequestBean()
                        requestObj.headers.Host = host.orEmpty().split(",").map { it.trim() }.filter { it.isNotEmpty() }
                        requestObj.path = path.orEmpty().split(",").map { it.trim() }.filter { it.isNotEmpty() }
                        tcpSetting.header.request = requestObj
                        sni = requestObj.headers.Host?.getOrNull(0)
                    }
                } else {
                    tcpSetting.header.type = "none"
                    sni = host
                }
                streamSettings.tcpSettings = tcpSetting
            }

            NetworkType.KCP.type -> {
                streamSettings.kcpSettings = StreamSettingsBean.KcpSettingsBean()
                val udpMaskList = mutableListOf<StreamSettingsBean.FinalMaskBean.MaskBean>()
                if (!headerType.isNullOrEmpty() && headerType != "none") {
                    val kcpHeaderType = when {
                        headerType == "wechat-video" -> "header-wechat"
                        else -> "header-$headerType"
                    }
                    udpMaskList.add(StreamSettingsBean.FinalMaskBean.MaskBean(
                        type = kcpHeaderType,
                        settings = if (headerType == "dns" && !host.isNullOrEmpty()) {
                            StreamSettingsBean.FinalMaskBean.MaskBean.MaskSettingsBean(
                                domain = host
                            )
                        } else {
                            null
                        }
                    ))
                }
                if (seed.isNullOrEmpty()) {
                    udpMaskList.add(StreamSettingsBean.FinalMaskBean.MaskBean(
                        type = "mkcp-original"
                    ))
                } else {
                    udpMaskList.add(StreamSettingsBean.FinalMaskBean.MaskBean(
                        type = "mkcp-aes128gcm",
                        settings = StreamSettingsBean.FinalMaskBean.MaskBean.MaskSettingsBean(
                            password = seed
                        )
                    ))
                }
                streamSettings.finalmask = StreamSettingsBean.FinalMaskBean(
                    udp = udpMaskList.toList()
                )
            }

            NetworkType.WS.type -> {
                val wssetting = StreamSettingsBean.WsSettingsBean()
                wssetting.headers.Host = host.orEmpty()
                sni = host
                wssetting.path = path ?: "/"
                streamSettings.wsSettings = wssetting
            }

            NetworkType.HTTP_UPGRADE.type -> {
                val httpupgradeSetting = StreamSettingsBean.HttpupgradeSettingsBean()
                httpupgradeSetting.host = host.orEmpty()
                sni = host
                httpupgradeSetting.path = path ?: "/"
                streamSettings.httpupgradeSettings = httpupgradeSetting
            }

            NetworkType.XHTTP.type -> {
                val xhttpSetting = StreamSettingsBean.XhttpSettingsBean()
                xhttpSetting.host = host.orEmpty()
                sni = host
                xhttpSetting.path = path ?: "/"
                xhttpSetting.mode = xhttpMode
                xhttpSetting.extra = JsonUtil.parseString(xhttpExtra)
                streamSettings.xhttpSettings = xhttpSetting
            }

            NetworkType.H2.type, NetworkType.HTTP.type -> {
                streamSettings.network = NetworkType.H2.type
                val h2Setting = StreamSettingsBean.HttpSettingsBean()
                h2Setting.host = host.orEmpty().split(",").map { it.trim() }.filter { it.isNotEmpty() }
                sni = h2Setting.host.getOrNull(0)
                h2Setting.path = path ?: "/"
                streamSettings.httpSettings = h2Setting
            }

//                    "quic" -> {
//                        val quicsetting = QuicSettingBean()
//                        quicsetting.security = quicSecurity ?: "none"
//                        quicsetting.key = key.orEmpty()
//                        quicsetting.header.type = headerType ?: "none"
//                        quicSettings = quicsetting
//                    }

            NetworkType.GRPC.type -> {
                val grpcSetting = StreamSettingsBean.GrpcSettingsBean()
                grpcSetting.multiMode = mode == "multi"
                grpcSetting.serviceName = serviceName.orEmpty()
                grpcSetting.authority = authority.orEmpty()
                grpcSetting.idle_timeout = 60
                grpcSetting.health_check_timeout = 20
                sni = authority
                streamSettings.grpcSettings = grpcSetting
            }

            NetworkType.HYSTERIA.type -> {
                val hysteriaSetting = StreamSettingsBean.HysteriaSettingsBean(
                    version = 2,
                    auth = profileItem.password.orEmpty(),
                    up = profileItem.bandwidthUp?.ifEmpty { "0" }.orEmpty(),
                    down = profileItem.bandwidthDown?.ifEmpty { "0" }.orEmpty(),
                    udphop = null
                )
                if (profileItem.portHopping.isNotNullEmpty()) {
                    hysteriaSetting.udphop = StreamSettingsBean.HysteriaSettingsBean.HysteriaUdpHopBean(
                        port = profileItem.portHopping,
                        interval = profileItem.portHoppingInterval
                            ?.trim()
                            ?.toIntOrNull()
                            ?.takeIf { it >= 5 }
                            ?: 30
                    )
                }
                streamSettings.hysteriaSettings = hysteriaSetting
            }
        }
        return sni
    }

    /**
     * Configures TLS or REALITY security settings for an outbound connection.
     *
     * Sets up security-related parameters like certificates, fingerprints, and SNI.
     *
     * @param streamSettings The stream settings to configure
     * @param profileItem The profile containing security configuration
     * @param sniExt An external SNI value to use if the profile doesn't specify one
     */
    fun populateTlsSettings(streamSettings: StreamSettingsBean, profileItem: ProfileItem, sniExt: String?) {
        val streamSecurity = profileItem.security.orEmpty()
        val allowInsecure = profileItem.insecure == true
        val sni = if (profileItem.sni.isNullOrEmpty()) {
            when {
                sniExt.isNotNullEmpty() && Utils.isDomainName(sniExt) -> sniExt
                profileItem.server.isNotNullEmpty() && Utils.isDomainName(profileItem.server) -> profileItem.server
                else -> sniExt
            }
        } else {
            profileItem.sni
        }

        streamSettings.security = streamSecurity.nullIfBlank()
        if (streamSettings.security == null) return
        val tlsSetting = StreamSettingsBean.TlsSettingsBean(
            allowInsecure = allowInsecure,
            serverName = sni.nullIfBlank(),
            fingerprint = profileItem.fingerPrint.nullIfBlank(),
            alpn =  profileItem.alpn?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }.takeIf { !it.isNullOrEmpty() },
            echConfigList = profileItem.echConfigList.nullIfBlank(),
            echForceQuery = profileItem.echForceQuery.nullIfBlank(),
            pinnedPeerCertSha256 = profileItem.pinnedCA256.nullIfBlank(),
            publicKey = profileItem.publicKey.nullIfBlank(),
            shortId = profileItem.shortId.nullIfBlank(),
            spiderX = profileItem.spiderX.nullIfBlank(),
            mldsa65Verify = profileItem.mldsa65Verify.nullIfBlank(),
        )
        if (streamSettings.security == AppConfig.TLS) {
            streamSettings.tlsSettings = tlsSetting
            streamSettings.realitySettings = null
        } else if (streamSettings.security == AppConfig.REALITY) {
            streamSettings.tlsSettings = null
            streamSettings.realitySettings = tlsSetting
        }
    }

    //endregion
}
