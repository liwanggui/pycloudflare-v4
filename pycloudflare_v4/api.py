# -*- coding: UTF-8 -*-

import json
import requests

cf_api_url = "https://api.cloudflare.com/client/v4/"


class CloudFlare(object):
    def __init__(self, email, token):
        self.EMAIL = email
        self.TOKEN = token
        self.headers = {
            'X-Auth-Email': self.EMAIL,
            'X-Auth-Key': self.TOKEN,
            'Content-Type': 'application/json'
        }

    class CONNError(Exception):
        pass

    class APIError(Exception):
        pass

    class WRAPPERError(Exception):
        pass

    def api_call_get(self, url, params=None):
        try:
            r = requests.get(cf_api_url + url, params=params, headers=self.headers)
        except (requests.ConnectionError,
                requests.RequestException,
                requests.HTTPError,
                requests.Timeout,
                requests.TooManyRedirects) as e:
            raise self.CONNError(str(e))
        try:
            api_result = r.json()
        except ValueError:
            raise self.APIError('JSON parse failed.')
        if api_result['result'] == 'error':
            raise self.APIError(api_result['msg'])
        return api_result

    def api_call_post(self, url, data=None):
        try:
            r = requests.post(cf_api_url + url, data=json.dumps(data), headers=self.headers)
        except (requests.ConnectionError,
                requests.RequestException,
                requests.HTTPError,
                requests.Timeout,
                requests.TooManyRedirects) as e:
            raise self.CONNError(str(e))
        try:
            api_result = r.json()
        except ValueError:
            raise self.APIError('JSON parse failed.')
        if api_result['result'] == 'error':
            raise self.APIError(api_result['msg'])
        return api_result

    def api_call_delete(self, uri, data={}):
        try:
            r = requests.delete(cf_api_url + uri, data=json.dumps(data), headers=self.headers)
        except (requests.ConnectionError,
                requests.RequestException,
                requests.HTTPError,
                requests.Timeout,
                requests.TooManyRedirects) as e:
            raise self.CONNError(str(e))
        try:
            api_result = r.json()
        except ValueError:
            raise self.APIError('JSON parse failed.')
        if not api_result['success']:
            raise self.APIError(api_result['errors'])
        return api_result

    def api_call_patch(self, uri, data={}):
        try:
            r = requests.patch(cf_api_url + uri, data=json.dumps(data), headers=self.headers)
        except (requests.ConnectionError,
                requests.RequestException,
                requests.HTTPError,
                requests.Timeout,
                requests.TooManyRedirects) as e:
            raise self.CONNError(str(e))
        try:
            api_result = r.json()
        except ValueError:
            raise self.APIError('JSON parse failed.')
        if api_result['result'] == 'error':
            raise self.APIError(api_result['msg'])
        return api_result

    def api_call_put(self, uri, data={}):
        try:
            r = requests.put(cf_api_url + uri, data=json.dumps(data), headers=self.headers)
        except (requests.ConnectionError,
                requests.RequestException,
                requests.HTTPError,
                requests.Timeout,
                requests.TooManyRedirects) as e:
            raise self.CONNError(str(e))
        try:
            api_result = r.json()
        except ValueError:
            raise self.APIError('JSON parse failed.')
        if api_result['result'] == 'error':
            raise self.APIError(api_result['msg'])
        elif api_result['errors']:
            raise self.APIError(str(api_result['errors']))
        return api_result

    ################################################################
    #  Zone (https://api.cloudflare.com/#zone)                     #
    ################################################################

    #  Get all zones
    def get_zones(self):
        """
        Returns an dictionary, where key is domain name and value is dict with everything CF could return,
        including zone ID which is used for any other operations.
        :return: dict
        """
        all_zones = {}
        try:
            intermediate_result = self.api_call_get("zones&per_page=50")
        except BaseException as e:
            raise self.APIError(str(e))

        if intermediate_result['success']:
            for i in intermediate_result['result']:
                all_zones[i['name']] = i

        pages = intermediate_result['result_info']['total_pages']
        if pages == 1:
            return all_zones

        for p in range(2, (pages + 1)):
            zones = self.api_call_get("zones&page={0}&per_page=50".format(p))
            if zones['success']:
                for i in zones['result']:
                    all_zones[i['name']] = i
            else:
                raise self.APIError(str(zones['errors']))

        return all_zones

    def create_zone(self, domain, jump_start=False):
        """
        Create Zone, https://api.cloudflare.com/#zone-create-zone
        :param domain: domain
        :param jump_start: Automatically attempt to fetch existing DNS records
        :return:
        """
        try:
            data = {'name': domain, 'jump_start': jump_start}
            result = self.api_call_post('zones', data)
            return result
        except BaseException as e:
            raise self.APIError(str(e))

    # Purge all cache for the zone
    def purge_everything(self, zone_id):
        """
        Deletes all cache in zone.
        :param zone_id:
        :return:
        """
        uri = "zones/" + str(zone_id) + "/purge_cache"
        data = {"purge_everything": True}
        return self.api_call_delete(uri, data)

    ################################################################
    #  Zone Settings (https://api.cloudflare.com/#zone-settings)   #
    ################################################################

    #  Get all zone settings info
    def get_all_zone_settings(self, zone_id):
        """
        This method returns human readable/scripting easy dictionary with all settings of a zone.
        :param zone_id:
        :return:
        """
        result = {}
        response = self.api_call_get("zones/" + str(zone_id) + "/settings")
        if response['success']:
            for i in response['result']:
                result[i['id']] = i
        return result

    def change_always_use_https(self, zone_id, always_use_https='off'):
        """
        https://api.cloudflare.com/#zone-settings-change-always-use-https-setting
        :param zone_id:
        :param always_use_https: valid values 'default', 'on', 'off'
        :return:
        """
        uri = 'zones/{}/settings/always_use_https'.format(zone_id)
        valid_values = ['default', 'on', 'off']

        if always_use_https not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if always_use_https == "default":
            set_always_use_https = "off"
        else:
            set_always_use_https = always_use_https

        data = {'value': set_always_use_https}
        return self.api_call_patch(uri, data)

    def change_always_online_setting(self, zone_id, always_online='off'):
        """
        https://api.cloudflare.com/#zone-settings-change-always-online-setting
        :param zone_id:
        :param always_online: valid values 'default', 'on', 'off'
        :return:
        """

        uri = "zones/{0}/settings/always_online".format(zone_id)
        valid_values = ["default", "on", "off"]

        if always_online not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if always_online == "default":
            set_always_online = "on"
        else:
            set_always_online = always_online

        data = {"value": "{0}".format(set_always_online)}

        return self.api_call_patch(uri, data)

    def change_automatic_https_rewrites_setting(self, zone_id, automatic_https_rewrites='on'):
        """
        https://api.cloudflare.com/#zone-settings-change-automatic-https-rewrites-setting
        :param zone_id:
        :param automatic_https_rewrites: valid values: on, off
        :return:
        """
        uri = "zones/{0}/settings/automatic_https_rewrites".format(zone_id)
        data = {"value": "{0}".format(automatic_https_rewrites)}
        return self.api_call_patch(uri, data)

    def change_browser_cache_ttl_setting(self, zone_id, browser_cache_ttl):
        """
        https://api.cloudflare.com/#zone-settings-change-browser-cache-ttl-setting
        :param zone_id:
        :param browser_cache_ttl:
        :return:
        """

        uri = "zones/{0}/settings/browser_cache_ttl".format(zone_id)
        valid_values = ["default", 30, 60, 300, 1200, 1800, 3600, 7200, 10800, 14400, 18000,
                        28800, 43200, 57600, 72000, 86400, 172800, 259200, 345600, 432000,
                        691200, 1382400, 2073600, 2678400, 5356800, 16070400, 31536000]

        if browser_cache_ttl not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if browser_cache_ttl == "default":
            set_browser_cache_ttl = 14400
        else:
            set_browser_cache_ttl = browser_cache_ttl

        data = {"value": set_browser_cache_ttl}

        return self.api_call_patch(uri, data)

    def change_browser_check_setting(self, zone_id, browser_check):
        """
        https://api.cloudflare.com/#zone-settings-change-browser-check-setting
        :param zone_id:
        :param browser_check:
        :return:
        """
        uri = "zones/{0}/settings/browser_check".format(zone_id)
        valid_values = ["default", "on", "off"]

        if browser_check not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if browser_check == "default":
            set_browser_check = "on"
        else:
            set_browser_check = browser_check

        data = {"value": "{0}".format(set_browser_check)}

        return self.api_call_patch(uri, data)

    def change_cache_level_setting(self, zone_id, cache_level):
        """
        https://api.cloudflare.com/#zone-settings-change-cache-level-setting
        :param zone_id:
        :param cache_level:
        :return:
        """
        uri = "zones/{0}/settings/cache_level".format(zone_id)
        valid_values = ["default", "aggressive", "basic", "simplified"]

        if cache_level not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if cache_level == "default":
            set_cache_level = "aggressive"
        else:
            set_cache_level = cache_level

        data = {"value": "{0}".format(set_cache_level)}

        return self.api_call_patch(uri, data)

    def change_challenge_ttl_setting(self, zone_id, challenge_ttl):
        """
        https://api.cloudflare.com/#zone-settings-change-challenge-ttl-setting
        :param zone_id:
        :param challenge_ttl:
        :return:
        """

        uri = "zones/{0}/settings/challenge_ttl".format(zone_id)
        valid_values = ["default", 300, 900, 1800, 2700, 3600, 7200, 10800, 14400,
                        28800, 57600, 86400, 604800, 2592000, 31536000]

        if challenge_ttl not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if challenge_ttl == "default":
            set_challenge_ttl = 1800
        else:
            set_challenge_ttl = challenge_ttl

        data = {"value": set_challenge_ttl}

        return self.api_call_patch(uri, data)

    def change_development_mode_setting(self, zone_id, development_mode):
        """
        https://api.cloudflare.com/#zone-settings-change-development-mode-setting
        :param zone_id:
        :param development_mode:
        :return:
        """
        uri = "zones/{0}/settings/development_mode".format(zone_id)
        valid_values = ["default", "on", "off"]

        if development_mode not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if development_mode == "default":
            set_development_mode = "off"
        else:
            set_development_mode = development_mode

        data = {"value": "{0}".format(set_development_mode)}

        return self.api_call_patch(uri, data)

    def change_email_obfuscation_setting(self, zone_id, email_obfuscation):
        """
        https://api.cloudflare.com/#zone-settings-change-email-obfuscation-setting
        :param zone_id:
        :param email_obfuscation:
        :return:
        """
        uri = "zones/{0}/settings/email_obfuscation".format(zone_id)
        valid_values = ["default", "on", "off"]

        if email_obfuscation not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if email_obfuscation == "default":
            set_email_obfuscation = "on"
        else:
            set_email_obfuscation = email_obfuscation

        data = {"value": "{0}".format(set_email_obfuscation)}

        return self.api_call_patch(uri, data)

    def change_origin_error_page_pass_thru_setting(self, zone_id, origin_error_page_pass_thru):
        """
        https://api.cloudflare.com/#zone-settings-change-enable-error-pages-on-setting
        :param zone_id:
        :param origin_error_page_pass_thru:
        :return:
        """
        uri = "zones/{0}/settings/origin_error_page_pass_thru".format(zone_id)
        valid_values = ["default", "on", "off"]

        if origin_error_page_pass_thru not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if origin_error_page_pass_thru == "default":
            set_origin_error_page_pass_thru = "off"
        else:
            set_origin_error_page_pass_thru = origin_error_page_pass_thru

        data = {"value": "{0}".format(set_origin_error_page_pass_thru)}

        return self.api_call_patch(uri, data)

    def change_sort_query_string_for_cache_setting(self, zone_id, sort_query_string_for_cache):
        """
        https://api.cloudflare.com/#zone-settings-change-enable-query-string-sort-setting
        :param zone_id:
        :param sort_query_string_for_cache:
        :return:
        """
        uri = "zones/{0}/settings/sort_query_string_for_cache".format(zone_id)
        valid_values = ["default", "on", "off"]

        if sort_query_string_for_cache not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if sort_query_string_for_cache == "default":
            set_sort_query_string_for_cache = "off"
        else:
            set_sort_query_string_for_cache = sort_query_string_for_cache

        data = {"value": "{0}".format(set_sort_query_string_for_cache)}

        return self.api_call_patch(uri, data)

    def change_hotlink_protection_setting(self, zone_id, hotlink_protection):
        """
        https://api.cloudflare.com/#zone-settings-change-hotlink-protection-setting
        :param zone_id:
        :param hotlink_protection: valid values 'default', 'on', 'off'
        :return:
        """
        uri = "zones/{0}/settings/hotlink_protection".format(zone_id)
        valid_values = ["default", "on", "off"]

        if hotlink_protection not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if hotlink_protection == "default":
            set_hotlink_protection = "off"
        else:
            set_hotlink_protection = hotlink_protection

        data = {"value": "{0}".format(set_hotlink_protection)}

        return self.api_call_patch(uri, data)

    def change_ip_geolocation_setting(self, zone_id, ip_geolocation):
        """
        https://api.cloudflare.com/#zone-settings-change-ip-geolocation-setting
        :param zone_id:
        :param ip_geolocation: valid values 'default', 'on', 'off'
        :return:
        """
        uri = "zones/{0}/settings/ip_geolocation".format(zone_id)
        valid_values = ["default", "on", "off"]

        if ip_geolocation not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if ip_geolocation == "default":
            set_ip_geolocation = "on"
        else:
            set_ip_geolocation = ip_geolocation

        data = {"value": "{0}".format(set_ip_geolocation)}

        return self.api_call_patch(uri, data)

    def change_ipv6_setting(self, zone_id, ipv6):
        """
        https://api.cloudflare.com/#zone-settings-change-ipv6-setting
        :param zone_id:
        :param ipv6: valid values 'default', 'on', 'off'
        :return:
        """
        uri = "zones/{0}/settings/ipv6".format(zone_id)
        valid_values = ["default", "on", "off"]

        if ipv6 not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if ipv6 == "default":
            set_ipv6 = "off"
        else:
            set_ipv6 = ipv6

        data = {"value": "{0}".format(set_ipv6)}

        return self.api_call_patch(uri, data)

    def change_minify_setting(self, zone_id, minify):
        """
        https://api.cloudflare.com/#zone-settings-change-minify-setting
        :param zone_id:
        :param minify:
        :return:
        """
        uri = "zones/{0}/settings/minify".format(zone_id)

        if minify == "default":
            set_minify = {"css": "off", "html": "off", "js": "off"}
        else:
            set_minify = minify

        data = {"value": "{0}".format(set_minify)}

        return self.api_call_patch(uri, data)

    def change_mobile_redirect_setting(self, zone_id, mobile_redirect):
        """
        https://api.cloudflare.com/#zone-settings-change-mobile-redirect-setting
        :param zone_id:
        :param mobile_redirect:
        :return:
        """
        uri = "zones/{0}/settings/mirage".format(zone_id)

        if mobile_redirect == "default":
            set_mobile_redirect = '{"status": "off", "mobile_subdomain": "m", "strip_uri": false}'
        else:
            set_mobile_redirect = mobile_redirect

        data = {"value": "{0}".format(set_mobile_redirect)}

        return self.api_call_patch(uri, data)

    def change_mirage_setting(self, zone_id, mirage):
        """
        https://api.cloudflare.com/#zone-settings-change-mirage-setting
        :param zone_id:
        :param mirage:
        :return:
        """
        uri = "zones/{0}/settings/mirage".format(zone_id)
        valid_values = ["default", "on", "off"]

        if mirage not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if mirage == "default":
            set_mirage = "off"
        else:
            set_mirage = mirage

        data = {"value": "{0}".format(set_mirage)}

        return self.api_call_patch(uri, data)

    def change_opportunistic_encryption_setting(self, zone_id, opportunistic_encryption):
        """
        https://api.cloudflare.com/#zone-settings-change-opportunistic-encryption-setting
        :param zone_id:
        :param opportunistic_encryption:
        :return:
        """
        uri = "zones/{0}/settings/opportunistic_encryption".format(zone_id)
        valid_values = ["default", "on", "off"]

        if opportunistic_encryption not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if opportunistic_encryption == "default":
            set_opportunistic_encryption = "on"
        else:
            set_opportunistic_encryption = opportunistic_encryption

        data = {"value": "{0}".format(set_opportunistic_encryption)}

        return self.api_call_patch(uri, data)

    def change_polish_setting(self, zone_id, polish):
        """
        https://api.cloudflare.com/#zone-settings-change-polish-setting
        :param zone_id:
        :param polish:
        :return:
        """
        uri = "zones/{0}/settings/polish".format(zone_id)
        valid_values = ["default", "lossless", "lossy"]

        if polish not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if polish == "default":
            set_polish = "off"
        else:
            set_polish = polish

        data = {"value": "{0}".format(set_polish)}

        return self.api_call_patch(uri, data)

    def change_prefetch_preload_setting(self, zone_id, prefetch_preload):
        """
        https://api.cloudflare.com/#zone-settings-change-prefetch-preload-setting
        :param zone_id:
        :param prefetch_preload:
        :return:
        """
        uri = "zones/{0}/settings/prefetch_preload".format(zone_id)
        valid_values = ["default", "on", "off"]

        if prefetch_preload not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if prefetch_preload == "default":
            set_prefetch_preload = "off"
        else:
            set_prefetch_preload = prefetch_preload

        data = {"value": "{0}".format(set_prefetch_preload)}

        return self.api_call_patch(uri, data)

    def change_response_buffering_setting(self, zone_id, response_buffering):
        """
        https://api.cloudflare.com/#zone-settings-change-response-buffering-setting
        :param zone_id:
        :param response_buffering:
        :return:
        """
        uri = "zones/{0}/settings/response_buffering".format(zone_id)
        valid_values = ["default", "on", "off"]

        if response_buffering not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if response_buffering == "default":
            set_response_buffering = "off"
        else:
            set_response_buffering = response_buffering

        data = {"value": "{0}".format(set_response_buffering)}

        return self.api_call_patch(uri, data)

    def change_rocket_loader_setting(self, zone_id, rocket_loader):
        """
        https://api.cloudflare.com/#zone-settings-change-rocket-loader-setting
        :param zone_id:
        :param rocket_loader:
        :return:
        """
        uri = "zones/{0}/settings/rocket_loader".format(zone_id)
        valid_values = ["default", "on", "off", "manual"]

        if rocket_loader not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if rocket_loader == "default":
            set_rocket_loader = "off"
        else:
            set_rocket_loader = rocket_loader

        data = {"value": "{0}".format(set_rocket_loader)}

        return self.api_call_patch(uri, data)

    def change_security_header_setting(self, zone_id, security_header):
        """
        https://api.cloudflare.com/#zone-settings-change-security-header-hsts-setting
        :param zone_id:
        :param security_header:
        :return:
        """
        uri = "zones/{0}/settings/security_header".format(zone_id)

        set_security_header = security_header

        data = {"value": "{0}".format(set_security_header)}

        return self.api_call_patch(uri, data)

    def change_security_level_setting(self, zone_id, security_level):
        """
        https://api.cloudflare.com/#zone-settings-change-security-level-setting
        :param zone_id:
        :param security_level:
        :return:
        """
        uri = "zones/{0}/settings/security_level".format(zone_id)
        valid_values = ["default", "essentially_off", "low", "medium", "high", "under_attack"]

        if security_level not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if security_level == "default":
            set_security_level = "medium"
        else:
            set_security_level = security_level

        data = {"value": "{0}".format(set_security_level)}

        return self.api_call_patch(uri, data)

    def change_server_side_exclude_setting(self, zone_id, server_side_exclude):
        """
        https://api.cloudflare.com/#zone-settings-change-server-side-exclude-setting
        :param zone_id:
        :param server_side_exclude:
        :return:
        """
        uri = "zones/{0}/settings/server_side_exclude".format(zone_id)
        valid_values = ["default", "on", "off"]

        if server_side_exclude not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if server_side_exclude == "default":
            set_server_side_exclude = "on"
        else:
            set_server_side_exclude = server_side_exclude

        data = {"value": "{0}".format(set_server_side_exclude)}

        return self.api_call_patch(uri, data)

    def change_ssl_setting(self, zone_id, ssl):
        """
        https://api.cloudflare.com/#zone-settings-change-ssl-setting
        :param zone_id:
        :param ssl:
        :return:
        """
        uri = "zones/{0}/settings/ssl".format(zone_id)
        valid_values = ["default", "off", "flexible", "full", "full_strict"]

        if ssl not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if ssl == "default":
            set_ssl = "off"
        else:
            set_ssl = ssl

        data = {"value": "{0}".format(set_ssl)}

        return self.api_call_patch(uri, data)

    def change_tls_client_auth_setting(self, zone_id, tls_client_auth):
        """
        https://api.cloudflare.com/#zone-settings-change-tls-client-auth-setting
        :param zone_id:
        :param tls_client_auth:
        :return:
        """
        uri = "zones/{0}/settings/tls_client_auth".format(zone_id)

        set_tls_client_auth = tls_client_auth

        data = {"value": "{0}".format(set_tls_client_auth)}

        return self.api_call_patch(uri, data)

    def change_true_client_ip_header_setting(self, zone_id, true_client_ip_header):
        """
        https://api.cloudflare.com/#zone-settings-change-true-client-ip-setting
        :param zone_id:
        :param true_client_ip_header:
        :return:
        """
        uri = "zones/{0}/settings/true_client_ip_header".format(zone_id)
        valid_values = ["default", "on", "off"]

        if true_client_ip_header not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if true_client_ip_header == "default":
            set_true_client_ip_header = "off"
        else:
            set_true_client_ip_header = true_client_ip_header

        data = {"value": "{0}".format(set_true_client_ip_header)}

        return self.api_call_patch(uri, data)

    def change_tls_1_2_only_setting(self, zone_id, tls_1_2_only):
        """
        https://api.cloudflare.com/#zone-settings-change-tls-1.2-setting
        :param zone_id:
        :param tls_1_2_only:
        :return:
        """
        uri = "zones/{0}/settings/tls_1_2_only".format(zone_id)
        valid_values = ["default", "on", "off"]

        if tls_1_2_only not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if tls_1_2_only == "default":
            set_tls_1_2_only = "off"
        else:
            set_tls_1_2_only = tls_1_2_only

        data = {"value": "{0}".format(set_tls_1_2_only)}

        return self.api_call_patch(uri, data)

    def change_tls_1_3_setting(self, zone_id, tls_1_3):
        """
        https://api.cloudflare.com/#zone-settings-change-tls-1.3-setting
        :param zone_id:
        :param tls_1_3:
        :return:
        """
        uri = "zones/{0}/settings/tls_1_3".format(zone_id)
        valid_values = ["default", "on", "off"]

        if tls_1_3 not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if tls_1_3 == "default":
            set_tls_1_3 = "off"
        else:
            set_tls_1_3 = tls_1_3

        data = {"value": "{0}".format(set_tls_1_3)}

        return self.api_call_patch(uri, data)

    def change_waf_setting(self, zone_id, waf):
        uri = "zones/{0}/settings/waf".format(zone_id)
        valid_values = ["default", "on", "off"]

        if waf not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if waf == "default":
            set_waf = "off"
        else:
            set_waf = waf

        data = {"value": "{0}".format(set_waf)}

        return self.api_call_patch(uri, data)

    def change_websockets_setting(self, zone_id, websockets):
        """
        https://api.cloudflare.com/#zone-settings-change-websockets-setting
        :param zone_id:
        :param websockets:
        :return:
        """
        uri = "zones/{0}/settings/websockets".format(zone_id)
        valid_values = ["default", "on", "off"]

        if websockets not in valid_values:
            raise self.WRAPPERError('valid values: {0}'.format(valid_values))

        if websockets == "default":
            set_websockets = "off"
        else:
            set_websockets = websockets

        data = {"value": "{0}".format(set_websockets)}

        return self.api_call_patch(uri, data)

    ################################################################
    #  DNS (https://api.cloudflare.com/#dns-records-for-a-zone)    #
    ################################################################

    # List DNS records (https://api.cloudflare.com/#dns-records-for-a-zone-list-dns-records)
    def dns_records(self, zone_id):
        """
        Returns list of records. Each record is the dict with everything CF could return.
        :param zone_id:
        :return: list
        """
        uri = 'zones/{}/dns_records'.format(zone_id)
        all_records = {}
        params = {'per_page': 200, 'page': 1}
        result = self.api_call_get(uri, params)

        if result['success']:
            for i in result['result']:
                all_records[i['id']] = i
        else:
            raise self.APIError(result['errors'])

        pages = result['result_info']['total_pages']
        if pages == '1':
            return all_records

        for page in range(2, (pages + 1)):
            params['page'] = page
            result = self.api_call_get(uri, params)
            if result['success']:
                for i in result['result']:
                    all_records[i['id']] = i
            else:
                raise self.APIError(result['errors'])
        return all_records

    def dns_records_create(self,
                           zone_id,
                           record_type,
                           record_name,
                           record_content,
                           record_ttl=1,
                           record_proxied=True,
                           record_priority=False
                           ):
        """
        https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
        :param zone_id:
        :param record_type: DNS record type
        :param record_name: DNS record name
        :param record_content: DNS record content
        :param record_ttl: Time to live for DNS record. Value of 1 is 'automatic'
        :param record_proxied:  Whether the record is receiving the performance and security benefits of Cloudflare
                                valid values: (true,false)
        :param record_priority: Used with some records like MX and SRV to determine priority.
                                If you do not supply a priority for an MX record,
                                a default value of 0 will be set
                                min value:0  max value:65535
        :return:
        """
        uri = 'zones/{}/dns_records'.format(zone_id)
        data = {
            "type": record_type,
            "name": record_name,
            "content": record_content,
            "ttl": record_ttl,
            "proxied": record_proxied
        }
        if record_type == 'MX':
            data['priority'] = record_priority
        return self.api_call_post(uri, data)

    def dns_records_update(self, zone_id, record_id, type=False, name=False, content=False, ttl=False, proxied=False):
        """
        https://api.cloudflare.com/#dns-records-for-a-zone-update-dns-record
        :param zone_id:
        :param record_id:
        :param type:
        :param name:
        :param content:
        :param ttl:
        :param proxied:
        :return:
        """
        uri = 'zones/{}/dns_records/{}'.format(zone_id, record_id)
        # valid_values_type = []
        valid_values_proxied = [False, True, 'false', 'true']
        valid_values_ttl = [False, 1, 120, 300, 600, 900, 1800, 2700, 3600, 7200, 18000, 43200]
        change_list = dict()
        if proxied not in valid_values_proxied:
            raise self.WRAPPERError('valid values: "false", "true" in quotes!')
        if int(ttl) not in valid_values_ttl:
            raise self.WRAPPERError(
                'valid values: 1 - Automatic, 120, 300, 600, 900, 1800, 2700, 3600, 7200, 18000, 43200')
        change_list['type'] = type
        change_list['name'] = name
        change_list['content'] = content
        change_list['ttl'] = ttl
        change_list['proxied'] = proxied
        original_data = self.dns_records(zone_id)[record_id]
        for k, v in change_list.items():
            if v:
                original_data[k] = v
        return self.api_call_put(uri, original_data)

    def dns_records_delete(self, zone_id, record_id):
        """
        https://api.cloudflare.com/#dns-records-for-a-zone-delete-dns-record
        :param zone_id:
        :param record_id:
        :return:
        """
        uri = "zones/{}/dns_records/{}".format(zone_id, record_id)
        return self.api_call_delete(uri)

    #################################################################################
    # Page Rules for a Zone (https://api.cloudflare.com/#cloudflare-ips-properties) #
    #################################################################################
    def page_rules(self, zone_id):
        """
        https://api.cloudflare.com/#page-rules-for-a-zone-list-page-rules
        :param zone_id:
        :return:
        """
        uri = 'zones/{}/pagerules'.format(zone_id)
        return self.api_call_get(uri)

    def page_rule_create(self, zone_id, targets, actions, status='active'):
        """
        https://api.cloudflare.com/#page-rules-for-a-zone-create-page-rule
        :param zone_id:
        :param targets:
        :param actions:
        :param status:
        :return:
        """
        uri = 'zones/{}/pagerules'.format(zone_id)
        data = {'targets': targets, 'actions': actions, 'status': status}
        return self.api_call_post(uri, data)

    def page_rule_details(self, zone_id, rule_id):
        """
        https://api.cloudflare.com/#page-rules-for-a-zone-page-rule-details
        :param zone_id:
        :param rule_id:
        :return:
        """
        uri = 'zones/{}/pagerules/{}'.format(zone_id, rule_id)
        return self.api_call_get(uri)

    def page_rule_edit(self, zone_id, rule_id, targets=None, actions=None, status='active'):
        """
        https://api.cloudflare.com/#page-rules-for-a-zone-edit-page-rule
        :param zone_id:
        :param rule_id:
        :param targets:
        :param actions:
        :param status:
        :return:
        """
        uri = 'zones/{}/pagerules/{}'.format(zone_id, rule_id)
        data = {'status': status}
        if targets:
            data['targets'] = targets
        if actions:
            data['actions'] = actions
        return self.api_call_patch(uri, data)

    def page_rule_delete(self, zone_id, rule_id):
        """
        https://api.cloudflare.com/#page-rules-for-a-zone-delete-page-rule
        :param zone_id:
        :param rule_id:
        :return:
        """
        uri = 'zones/{}/pagerules/{}'.format(zone_id, rule_id)
        return self.api_call_delete(uri)

    ############################################################################################################
    # User-level Firewall Access Rule (https://api.cloudflare.com/#user-level-firewall-access-rule-properties) #
    ############################################################################################################
    def firewall_user_access_rules(self):
        """
        https://api.cloudflare.com/#user-level-firewall-access-rule-list-access-rules
        :return:
        """
        all_rules = {}
        uri = 'user/firewall/access_rules/rules'
        params = {'per_page': 200, 'page': 1}
        result = self.api_call_get(uri, params)

        if result['success']:
            for i in result['result']:
                all_rules[i['id']] = i
        else:
            raise self.APIError(result['errors'])

        pages = result['result_info']['total_pages']
        if pages == '1':
            return all_rules

        for page in range(2, (pages + 1)):
            params['page'] = page
            result = self.api_call_get(uri, params)
            if result['success']:
                for i in result['result']:
                    all_rules[i['id']] = i
            else:
                raise self.APIError(result['errors'])
        return all_rules

    def firewall_user_access_rule_create(self, mode, configuration, notes):
        """
        https://api.cloudflare.com/#user-level-firewall-access-rule-create-access-rule
        :param mode:
        :param configuration:
        :param notes:
        :return:
        """
        uri = 'user/firewall/access_rules/rules'
        data = {'mode': mode, 'configuration': configuration, 'notes': notes}
        return self.api_call_post(uri, data)

    def firewall_user_access_rule_ip(self, ip, mode="block", notes=None):
        """

        :param ip: ip or ip range
        :param mode: block, challenge, whitelist, js_challenge
        :param notes:
        :return:
        """
        if ip[-3] == '/':
            configuration = {"target": "ip_range", "value": ip}
        else:
            configuration = {"target": "ip", "value": ip}
        notes = notes or '{} {}'.format(mode, ip)
        return self.firewall_user_access_rule_create(mode, configuration, notes)

    def firewall_user_access_rule_country(self, country, mode="block", notes=None):
        """

        :param country:
        :param mode: block, challenge, whitelist, js_challenge
        :param notes:
        :return:
        """
        configuration = {"target": "country", "value": country}
        notes = notes or '{} {}'.format(mode, country)
        return self.firewall_user_access_rule_create(mode, configuration, notes)

    def firewall_user_access_rule_edit(self, rule_id, mode=None, notes=None):
        """
        https://api.cloudflare.com/#user-level-firewall-access-rule-edit-access-rule
        :param rule_id:
        :param mode:
        :param notes:
        :return:
        """
        uri = 'user/firewall/access_rules/rules/{}'.format(rule_id)
        data = {}
        if mode:
            data['mode'] = mode
        if notes:
            data['notes'] = notes
        if not data:
            raise self.APIError('missing parameters')
        return self.api_call_patch(uri, data)

    def firewall_user_access_rule_delete(self, rule_id):
        """
        https://api.cloudflare.com/#user-level-firewall-access-rule-delete-access-rule
        :param rule_id:
        :return:
        """
        uri = 'user/firewall/access_rules/rules/{}'.format(rule_id)
        return self.api_call_delete(uri)

    ############################################################################################################
    # Firewall Access Rule for a Zone (https://api.cloudflare.com/#firewall-access-rule-for-a-zone-properties) #
    ############################################################################################################
    def firewall_zone_access_rules(self, zone_id):
        """
        https://api.cloudflare.com/#firewall-access-rule-for-a-zone-list-access-rules
        :param zone_id:
        :return:
        """
        all_rules = {}
        uri = 'zones/{}/firewall/access_rules/rules'.format(zone_id)
        params = {'per_page': 200, 'page': 1}
        result = self.api_call_get(uri, params)

        if result['success']:
            for i in result['result']:
                all_rules[i['id']] = i
        else:
            raise self.APIError(result['errors'])
        pages = result['result_info']['total_pages']
        if pages == '1':
            return all_rules

        for page in range(2, (pages + 1)):
            params['page'] = page
            result = self.api_call_get(uri, params)
            if result['success']:
                for i in result['result']:
                    all_rules[i['id']] = i
            else:
                raise self.APIError(result['errors'])
        return all_rules

    def firewall_zone_access_rule_create(self, zone_id, mode, configuration, notes):
        """
        https://api.cloudflare.com/#firewall-access-rule-for-a-zone-create-access-rule
        :param zone_id:
        :param mode:
        :param configuration:
        :param notes:
        :return:
        """
        uri = 'zones/{}/firewall/access_rules/rules'.format(zone_id)
        data = {'mode': mode, 'configuration': configuration, 'notes': notes}
        return self.api_call_post(uri, data)

    def firewall_zone_access_rule_ip(self, zone_id, ip, mode="block", notes=None):
        """
        :param zone_id:
        :param ip:
        :param mode: block, challenge, whitelist, js_challenge
        :param notes:
        :return:
        """

        if ip[-3] == '/':
            configuration = {"target": "ip_range", "value": ip}
        else:
            configuration = {"target": "ip", "value": ip}

        notes = notes or '{} {}'.format(mode, ip)

        return self.firewall_zone_access_rule_create(zone_id, mode, configuration, notes)

    def firewall_zone_access_rule_country(self, zone_id, country, mode="block", notes=None):
        """
        :param zone_id:
        :param country:
        :param mode: block, challenge, whitelist, js_challenge
        :param notes:
        :return:
        """
        configuration = {"target": "country", "value": country}
        notes = notes or '{} {}'.format(mode, country)
        return self.firewall_zone_access_rule_create(zone_id, mode, configuration, notes)

    def firewall_zone_access_rule_edit(self, zone_id, rule_id, mode=None, notes=None):
        """
        https://api.cloudflare.com/#firewall-access-rule-for-a-zone-edit-access-rule
        :param zone_id:
        :param rule_id:
        :param mode:
        :param notes:
        :return:
        """
        uri = 'zones/{}/firewall/access_rules/rules/{}'.format(zone_id, rule_id)
        data = {}
        if mode:
            data['mode'] = mode
        if notes:
            data['notes'] = notes
        if not data:
            raise self.APIError('missing parameters')
        return self.api_call_patch(uri, data)

    def firewall_zone_access_rule_delete(self, zone_id, rule_id):
        """
        https://api.cloudflare.com/#firewall-access-rule-for-a-zone-delete-access-rule
        :param zone_id:
        :param rule_id:
        :return:
        """
        uri = 'zones/{}/firewall/access_rules/rules/{}'.format(zone_id, rule_id)
        return self.api_call_delete(uri)

    ##########################################################################
    # CloudFlare IPs (https://api.cloudflare.com/#cloudflare-ips-properties) #
    ##########################################################################
    def cf_ips(self):
        """
        Get Cloudflare IPs
        :return: dict
        """
        uri = "ips"
        response = self.api_call_get(uri)
        if response['success']:
            return response['result']
