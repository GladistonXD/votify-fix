from __future__ import annotations

import functools
import json
import logging
import re
import time
import typing
from http.cookiejar import MozillaCookieJar
from pathlib import Path

import base62
import requests

import secrets
import websocket
import threading

from .device_flow import SpotifyDeviceFlow
from .totp import TOTP
from .utils import check_response

logger = logging.getLogger("votify")


class SpotifyApi:
    SPOTIFY_HOME_PAGE_URL = "https://open.spotify.com/"
    SPOTIFY_COOKIE_DOMAIN = ".spotify.com"
    CLIENT_VERSION = "1.2.70.61.g856ccd63"
    LYRICS_API_URL = "https://spclient.wg.spotify.com/color-lyrics/v2/track/{track_id}"
    METADATA_API_URL = "https://api-partner.spotify.com/pathfinder/v2/query"
    GID_METADATA_API_URL = "https://spclient.wg.spotify.com/metadata/4/{media_type}/{gid}?market=from_token"
    PATHFINDER_API_URL = "https://api-partner.spotify.com/pathfinder/v1/query"
    VIDEO_MANIFEST_API_URL = "https://gue1-spclient.spotify.com/manifests/v9/json/sources/{gid}/options/supports_drm"
    TRACK_PLAYBACK_API_URL = "https://gue1-spclient.spotify.com/track-playback/v1/media/spotify:{media_type}:{media_id}"
    PLAYPLAY_LICENSE_API_URL = (
        "https://gew4-spclient.spotify.com/playplay/v1/key/{file_id}"
    )
    WIDEVINE_LICENSE_API_URL = (
        "https://gue1-spclient.spotify.com/widevine-license/v1/{type}/license"
    )
    SEEK_TABLE_API_URL = "https://seektables.scdn.co/seektable/{file_id}.json"
    TRACK_CREDITS_API_URL = "https://spclient.wg.spotify.com/track-credits-view/v0/experimental/{track_id}/credits"
    STREAM_URLS_API_URL = (
        "https://gue1-spclient.spotify.com/storage-resolve/v2/files/audio/interactive/11/"
        "{file_id}?version=10000000&product=9&platform=39&alt=json"
    )
    EXTEND_TRACK_COLLECTION_WAIT_TIME = 0.5
    SERVER_TIME_URL = "https://open.spotify.com/api/server-time"
    SESSION_TOKEN_URL = "https://open.spotify.com/api/token"
    CLIENT_TOKEN_URL = "https://clienttoken.spotify.com/v1/clienttoken"

    def __init__(
        self, *,
        secrets_url: str,
        sp_dc: str | None = None,
        use_device_flow: bool = False,
    ) -> None:
        self.session = requests.Session()

        secrets = self.session.get(secrets_url)
        check_response(secrets)
        totp_version, secrets_ciphertext = max(secrets.json().items(), key=lambda item: int(item[0]))

        self.totp = TOTP(version=totp_version, ciphertext=secrets_ciphertext)
        self.sp_dc = sp_dc
        self.use_device_flow = use_device_flow
        self._set_session()

    @classmethod
    def from_cookies_file(cls, cookies_path: Path, **kwargs) -> SpotifyApi:
        cookies = MozillaCookieJar(cookies_path)
        cookies.load(ignore_discard=True, ignore_expires=True)
        parse_cookie = lambda name: next(
            (
                cookie.value
                for cookie in cookies
                if cookie.name == name and cookie.domain == cls.SPOTIFY_COOKIE_DOMAIN
            ),
            None,
        )
        sp_dc = parse_cookie("sp_dc")
        if sp_dc is None:
            raise ValueError(
                '"sp_dc" cookie not found in cookies. '
                "Make sure you have exported the cookies from the Spotify homepage and are logged in."
            )
        return cls(sp_dc=sp_dc, **kwargs)

    def _set_session(self) -> None:
        self._setup_session_headers()
        self._setup_authorization()
        self._setup_user_profile()

    def _setup_session_headers(self) -> None:
        headers = {
            "accept": "application/json",
            "accept-language": "en-US",
            "content-type": "application/json",
            "origin": self.SPOTIFY_HOME_PAGE_URL,
            "priority": "u=1, i",
            "referer": self.SPOTIFY_HOME_PAGE_URL,
            "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "spotify-app-version": self.CLIENT_VERSION,
            "app-platform": "WebPlayer",
        }
        self.session.headers.update(headers)

        if self.sp_dc:
            self.session.cookies.update({"sp_dc": self.sp_dc})

    def _get_server_time(self) -> int:
        response = self.session.get(self.SERVER_TIME_URL)
        check_response(response)
        return 1e3 * response.json()["serverTime"]

    def set_token_headers(self, token: str, client_token: str | None = None) -> None:

        self.session.headers.update(
            {
                "authorization": f"Bearer {token}",
                "client-token": client_token
            }
        )

    def _setup_authorization_with_totp(self) -> None:
        if "Authorization" in self.session.headers:
            del self.session.headers["Authorization"]
        server_time = self._get_server_time()
        totp = self.totp.generate(timestamp=server_time)
        response = self.session.get(
            self.SESSION_TOKEN_URL,
            params={
                "reason": "init",
                "productType": "web-player",
                "totp": totp,
                "totpServer": totp,
                "totpVer": str(self.totp.version),
            },
        )
        check_response(response)
        authorization_info = response.json()
        if not authorization_info.get("accessToken"):
            raise ValueError("Failed to retrieve access token.")
        
        response = self.session.post(self.CLIENT_TOKEN_URL,
                json = {
                    'client_data': {
                        'client_version': self.CLIENT_VERSION,
                        'client_id': authorization_info['clientId'],
                        'js_sdk_data': {}
                    }
                },
                headers = {
                    'Accept': 'application/json',
                }
        )
        check_response(response)
        client_token = response.json()
        if not client_token.get("granted_token"):
            raise ValueError("Failed to retrieve granted token.")
        
        self.set_token_headers(authorization_info["accessToken"], client_token["granted_token"]["token"])
        self.session_auth_expire_time = (
            authorization_info["accessTokenExpirationTimestampMs"] / 1000
        )   

    def _setup_authorization(self) -> None:
        if self.use_device_flow:
            self._setup_authorization_with_device_flow()
        else:
            self._setup_authorization_with_totp()

    def _setup_authorization_with_device_flow(self) -> None:
        device_flow = SpotifyDeviceFlow(self.sp_dc)
        token_data = device_flow.get_token()
        self.set_token_headers(token_data["access_token"])
        self.session_auth_expire_time = (
            int(time.time()) + token_data["expires_in"]
        ) * 1000

    def _refresh_session_auth(self) -> None:
        timestamp_session_expire = int(self.session_auth_expire_time)
        timestamp_now = time.time()
        if timestamp_now < timestamp_session_expire:
            return
        self._setup_authorization()

    def _setup_user_profile(self) -> None:
        payload = {
            "variables": {},
            "operationName": "accountAttributes",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "24aaa3057b69fa91492de26841ad199bd0b330ca95817b7a4d6715150de01827"
                }
            }
        }

        response = self.session.post(
            self.METADATA_API_URL,
            json=payload,
        )
        check_response(response)
        self.user_profile = response.json()

    @staticmethod
    def media_id_to_gid(media_id: str) -> str:
        return hex(base62.decode(media_id, base62.CHARSET_INVERTED))[2:].zfill(32)

    @staticmethod
    def gid_to_media_id(gid: str) -> str:
        return base62.encode(int(gid, 16), charset=base62.CHARSET_INVERTED).zfill(22)

    def get_gid_metadata(
        self,
        gid: str,
        media_type: str,
    ) -> dict:
        self._refresh_session_auth()
        response = self.session.get(self.GID_METADATA_API_URL.format(gid=gid, media_type=media_type))
        check_response(response)
        return response.json()

    def get_track_playback_info(
        self,
        media_id: str,
        media_type: str
    ) -> dict | None:
        self._refresh_session_auth()
        params = {
            "manifestFileFormat": [
                "file_ids_mp4",
                "manifest_ids_video"
            ]
        }
        response = self.session.get(
            self.TRACK_PLAYBACK_API_URL.format(
                media_type=media_type,
                media_id=media_id
            ),
            params=params
        )
        return response.json()

    def get_decryption_keys_part1(self, track_id, audio_quality, times):

        if not hasattr(self, 'execution_count'):
            self.execution_count = 0

        if not hasattr(self, 'global_seq_num'):
            self.global_seq_num = 2

        if not hasattr(self, 'cached_device_id') or self.execution_count >= 1:
            self.cached_device_id = secrets.token_hex(16)
            self.execution_count = 0
            #print(f"{self.cached_device_id}")

        self.execution_count += 1
        local_device_id = self.cached_device_id

        try:
            ACCESS_TOKEN = self.session.headers["Authorization"].replace("Bearer ", "")
            CLIENT_TOKEN = self.session.headers["client-token"]
        except:
            return None

        WS_URL = f"wss://dealer.spotify.com/?access_token={ACCESS_TOKEN}"
        URL_REGISTRO = f"https://gue1-spclient.spotify.com/track-playback/v1/devices"
        URL_COMMAND = f"https://gue1-spclient.spotify.com/connect-state/v1/player/command/from/{local_device_id}/to/{local_device_id}"
        URL_STATE = f"https://gue1-spclient.spotify.com/track-playback/v1/devices/{local_device_id}/state"
        URL_MEMBER_STATE = f"https://gue1-spclient.spotify.com/connect-state/v1/devices/hobs_{local_device_id}"
        URL_TELEMETRY = "https://gue1-spclient.spotify.com/melody/v1/msg/batch"

        class Context:
            conn_id = None
            machine_id = None
            state_id = None
            file_id = None
            found = False
            stop_event = threading.Event()
            ws_client = None

        ctx = Context()

        def find_key(data, target):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k == target: return v
                    res = find_key(v, target)
                    if res: return res
            elif isinstance(data, list):
                for item in data:
                    res = find_key(item, target)
                    if res: return res
            return None

        def scan_and_extract(obj):
            if not obj or not isinstance(obj, dict): return
            tracks = []
            if "tracks" in obj:
                tracks = obj.get("tracks") or []
            elif "track" in obj:
                tracks = [obj.get("track")]
            elif "player_state" in obj:
                ps = obj.get("player_state") or {}
                if "track" in ps: tracks.append(ps.get("track"))
                if "tracks" in ps: tracks.extend(ps.get("tracks") or [])

            for track in tracks:
                if not isinstance(track, dict): continue
                uri = track.get("uri") or ""
                meta = track.get("metadata") or {}
                if not uri: uri = meta.get("uri") or ""
                linked_from = meta.get("linked_from_uri") or ""

                if (track_id in uri) or (linked_from and track_id in linked_from):
                    manifest = track.get("manifest")
                    if manifest:
                        fid = None
                        for key in ["file_ids_mp4", "file_ids_mp4_dual", "file_ids_mp3"]:
                            mp4s = manifest.get(key) or []
                            for f in mp4s:
                                if f.get("bitrate") == int(audio_quality):
                                    fid = f.get("file_id")
                                    break
                            if fid: break
                        if fid:
                            ctx.file_id = fid
                            ctx.found = True

        def on_message(ws, message):
            try:
                data = json.loads(message)
                if "headers" in data:
                    h = data.get("headers") or {}
                    if "Spotify-Connection-Id" in h:
                        ctx.conn_id = h["Spotify-Connection-Id"]

                new_mid = find_key(data, "state_machine_id")
                if new_mid and new_mid != ctx.machine_id: ctx.machine_id = new_mid

                new_sid = find_key(data, "state_id")
                if new_sid and new_sid != ctx.state_id: ctx.state_id = new_sid

                if "payloads" in data:
                    payloads = data.get("payloads") or []
                    for p in payloads:
                        if "cluster" in p: scan_and_extract(p.get("cluster"))
                        if "state_machine" in p: scan_and_extract(p.get("state_machine"))
                scan_and_extract(data)
            except:
                pass

        def websocket_ping_loop():
            while not ctx.stop_event.is_set():
                time.sleep(60)
                if ctx.ws_client:
                    try:
                        ctx.ws_client.send('{"type":"ping"}')
                    except:
                        break

        def start_socket():
            ctx.ws_client = websocket.WebSocketApp(WS_URL, on_message=on_message)
            ctx.ws_client.run_forever()

        threading.Thread(target=start_socket, daemon=True).start()
        threading.Thread(target=websocket_ping_loop, daemon=True).start()

        for _ in range(100):
            if ctx.conn_id: break
            time.sleep(0.1)
        if not ctx.conn_id:
            return None

        HEADERS_BASE = {
            "accept": "application/json",
            "authorization": f"Bearer {ACCESS_TOKEN}",
            "client-token": CLIENT_TOKEN,
            "x-spotify-connection-id": ctx.conn_id,
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        reg_payload = {
            "device": {
                "brand": "spotify",
                "capabilities": {
                    "change_volume": True, "enable_play_token": True, "supports_file_media_type": True,
                    "play_token_lost_behavior": "pause", "disable_connect": False, "audio_podcasts": True,
                    "video_playback": True,
                    "manifest_formats": ["file_ids_mp3", "file_urls_mp3", "manifest_urls_audio_ad",
                                         "manifest_ids_video", "file_urls_external", "file_ids_mp4",
                                         "file_ids_mp4_dual"]
                },
                "device_id": local_device_id, "device_type": "computer", "metadata": {},
                "model": "web_player", "name": "Web Player (Chrome)",
                "platform_identifier": "web_player windows 10;chrome 120.0.0.0;desktop", "is_group": False
            },
            "connection_id": ctx.conn_id, "client_version": "harmony:4.43.2-a61ecaf5",
            "volume": 65535, "outro_endcontent_snooping": False
        }
        requests.post(URL_REGISTRO, headers=HEADERS_BASE, json=reg_payload)

        connect_payload = {
            "member_type": "CONNECT_STATE",
            "device": {"device_info": {
                "capabilities": {"can_be_player": False, "hidden": True, "needs_full_player_state": True}}}
        }
        requests.put(URL_MEMBER_STATE, headers=HEADERS_BASE, json=connect_payload)

        track_uri = f"spotify:track:{track_id}"
        current_command_id = secrets.token_hex(16)

        cmd_payload = {
            "command": {
                "context": {"uri": track_uri, "url": f"context://{track_uri}", "metadata": {}},
                "play_origin": {
                    "feature_identifier": "track",
                    "feature_version": "open-server_2026-03-06_1772762959532_dc79fa1",
                    "referrer_identifier": "home"
                },
                "options": {"license": "tft", "skip_to": {}, "seek_to": 30000, "player_options_override": {}},
                "logging_params": {"page_instance_ids": [], "interaction_ids": [],
                                   "command_id": current_command_id},
                "endpoint": "play"
            }
        }

        requests.post(URL_COMMAND, headers=HEADERS_BASE, json=cmd_payload)

        timeout = 0
        while not ctx.stop_event.is_set() and timeout < 60:
            if ctx.found:
                break

            time.sleep(0.5)
            timeout += 1

        shared_state = None

        if ctx.file_id:
            try:
                playback_id = secrets.token_hex(16)
                next_playback_id = secrets.token_hex(16)
                session_id = str(int(time.time() * 1000))
                current_time_ms = int(time.time() * 1000)

                telemetry_headers = HEADERS_BASE.copy()
                telemetry_headers["content-type"] = "text/plain;charset=UTF-8"

                telemetry_payload = {
                    "messages": [
                        {
                            "type": "track_stream_verification",
                            "message": {
                                "play_track": track_uri, "playback_id": playback_id, "ms_played": 16,
                                "ms_nominal_played": 16, "session_id": session_id, "sequence_id": 2,
                                "next_playback_id": next_playback_id, "playback_service": "track-playback"
                            }
                        },
                        {
                            "type": "jssdk_playback_stats",
                            "message": {
                                "play_track": track_uri, "file_id": ctx.file_id, "playback_id": playback_id,
                                "internal_play_id": "17", "memory_cached": True, "persistent_cached": False,
                                "audio_format": "mp4", "video_format": "", "manifest_id": ctx.file_id,
                                "protected": True, "key_system": "com.widevine.alpha", "key_system_impl": "native",
                                "urls_json": '{"version":"1.0.0","urls":[{"url":"","segments":3,"avg_bw":0}]}',
                                "start_time": current_time_ms - 30000, "end_time": current_time_ms,
                                "external_start_time": 0, "ms_play_latency": 143, "ms_init_latency": 135,
                                "ms_head_latency": 609, "ms_first_bytes_latency": 612, "ms_manifest_latency": None,
                                "ms_resolve_latency": None, "ms_license_session_latency": 0,
                                "ms_license_generation_latency": 141, "ms_license_request_latency": 312,
                                "ms_license_update_latency": 141, "ms_played": 16, "ms_nominal_played": 16,
                                "ms_file_duration": times, "ms_actual_duration": times, "ms_metadata_duration": 0,
                                "ms_start_position": 30000, "ms_end_position": 30016, "ms_initial_rebuffer": 141,
                                "ms_seek_rebuffer": 0, "ms_seek_rebuffer_longest": 0, "ms_stall_rebuffer": 0,
                                "ms_stall_rebuffer_longest": 0, "ms_played_per_surface": {}, "ms_played_visible": 0,
                                "n_stalls": 0, "n_rendition_upgrade": 0, "n_rendition_downgrade": 0,
                                "bps_bandwidth_max": 0, "bps_bandwidth_min": 0, "bps_bandwidth_avg": 0,
                                "n_seekback": 0, "n_seekforward": 0, "audio_start_bitrate": audio_quality,
                                "video_start_bitrate": None, "start_bitrate": audio_quality, "time_weighted_bitrate": 0,
                                "reason_start": "trackdone", "reason_end": "remote", "initially_paused": False,
                                "had_error": False, "n_warnings": 0, "n_navigator_offline": 0,
                                "session_id": session_id, "sequence_id": 2, "client_id": "", "correlation_id": "",
                                "n_dropped_video_frames": 0, "n_total_video_frames": 0, "resolution_max": 0,
                                "resolution_min": 0, "total_bytes": 496099, "strategy": "MSE",
                                "ms_played_per_audio_format": {f"mp4a.40.2;{audio_quality}": 16},
                                "ms_played_per_video_format": {}
                            }
                        }
                    ],
                    "sdk_id": "harmony:4.64.0", "platform": "web_player windows 10;chrome 117.0.0.0;desktop",
                    "client_version": "0.0.0"
                }

                requests.post(URL_TELEMETRY, headers=telemetry_headers, data=json.dumps(telemetry_payload))

                next_machine_id = secrets.token_urlsafe(22)


                connect_command_payload = {
                    "messages": [
                        {
                            "type": "jssdk_connect_command",
                            "message": {
                                "ms_ack_duration": 1013, "ms_request_latency": 625,
                                "command_id": current_command_id,
                                "command_type": "play", "target_device_brand": "spotify",
                                "target_device_model": "web_player",
                                "target_device_client_id": "d8a5ed958d274c2e8ee717e6a4b0971d",
                                "target_device_id": local_device_id, "interaction_ids": "",
                                "play_origin": "{\"feature_identifier\":\"track\",\"feature_version\":\"open-server_2026-03-06_1772762959532_dc79fa1\",\"referrer_identifier\":\"home\"}",
                                "result": "success", "http_response": "", "http_status_code": 200
                            }
                        }
                    ],
                    "sdk_id": "harmony:4.64.0-63a650210",
                    "platform": "web_player windows 10;chrome 117.0.0.0;desktop",
                    "client_version": "0.0.0"
                }
                requests.post(URL_TELEMETRY, headers=telemetry_headers, data=json.dumps(connect_command_payload))

                self.global_seq_num += 1
                before_load_payload = {
                    "seq_num": self.global_seq_num,
                    "state_ref": {
                        "state_machine_id": next_machine_id,
                        "state_id": next_playback_id,
                        "paused": False
                    },
                    "sub_state": {
                        "playback_speed": 1, "position": 0, "duration": times,
                        "media_type": "AUDIO", "bitrate": audio_quality, "audio_quality": "HIGH",
                        "format": 10
                    },
                    "debug_source": "before_track_load"
                }
                requests.put(URL_STATE, headers=HEADERS_BASE, json=before_load_payload)

                self.global_seq_num += 1
                speed_0_payload = {
                    "seq_num": self.global_seq_num,
                    "state_ref": {"state_machine_id": next_machine_id, "state_id": next_playback_id,
                                  "paused": False},
                    "sub_state": {"playback_speed": 0, "position": 0, "duration": times, "media_type": "AUDIO",
                                  "bitrate": audio_quality, "audio_quality": "HIGH", "format": 10},
                    "previous_position": 0, "debug_source": "speed_changed"
                }
                requests.put(URL_STATE, headers=HEADERS_BASE, json=speed_0_payload)

                self.global_seq_num += 1
                speed_1_payload = {
                    "seq_num": self.global_seq_num,
                    "state_ref": {"state_machine_id": next_machine_id, "state_id": next_playback_id,
                                  "paused": False},
                    "sub_state": {"playback_speed": 1, "position": 0, "duration": times, "media_type": "AUDIO",
                                  "bitrate": audio_quality, "audio_quality": "HIGH", "format": 10},
                    "debug_source": "speed_changed"
                }
                requests.put(URL_STATE, headers=HEADERS_BASE, json=speed_1_payload)

                playback_start_payload = {
                    "messages": [{"type": "jssdk_playback_start",
                                  "message": {"play_track": track_uri, "file_id": ctx.file_id,
                                              "playback_id": next_playback_id, "session_id": session_id,
                                              "ms_start_position": 0, "initially_paused": False,
                                              "client_id": "",
                                              "correlation_id": "", "feature_identifier": ""}}],
                    "sdk_id": "harmony:4.64.0", "platform": "web_player windows 10;chrome 117.0.0.0;desktop",
                    "client_version": "0.0.0"
                }
                requests.post(URL_TELEMETRY, headers=telemetry_headers, data=json.dumps(playback_start_payload))

                shared_state = {
                    "ctx": ctx,
                    "times": times,
                    "track_uri": track_uri,
                    "local_device_id": local_device_id,
                    "URL_STATE": URL_STATE,
                    "URL_TELEMETRY": URL_TELEMETRY,
                    "HEADERS_BASE": HEADERS_BASE,
                    "telemetry_headers": telemetry_headers,
                    "next_machine_id": next_machine_id,
                    "next_playback_id": next_playback_id,
                    "session_id": session_id,
                    "current_time_ms": current_time_ms
                }

            except Exception as e:
                print(f"{e}")

        if not shared_state:
            ctx.stop_event.set()
            if ctx.ws_client:
                ctx.ws_client.close()
        return shared_state


    def get_decryption_keys_part2(self, shared_state, audio_quality):
        if not shared_state:
            return None

        ctx = shared_state["ctx"]
        times = shared_state["times"]
        track_uri = shared_state["track_uri"]
        local_device_id = shared_state["local_device_id"]
        URL_STATE = shared_state["URL_STATE"]
        URL_TELEMETRY = shared_state["URL_TELEMETRY"]
        HEADERS_BASE = shared_state["HEADERS_BASE"]
        telemetry_headers = shared_state["telemetry_headers"]
        next_machine_id = shared_state["next_machine_id"]
        next_playback_id = shared_state["next_playback_id"]
        session_id = shared_state["session_id"]
        current_time_ms = shared_state["current_time_ms"]

        try:
            self.global_seq_num += 1
            started_playing = {
                "seq_num": self.global_seq_num,
                "state_ref": {"state_machine_id": ctx.machine_id, "state_id": ctx.state_id,
                              "paused": False},
                "sub_state": {
                    "playback_speed": 1, "position": 1054, "duration": times,
                    "media_type": "AUDIO", "bitrate": audio_quality, "audio_quality": "HIGH",
                    "format": 10, "is_video_on": False,
                },
                "previous_position": 1054,
                "debug_source": "started_playing",
            }
            requests.put(URL_STATE, headers=HEADERS_BASE, json=started_playing)

            self.global_seq_num += 1
            played_threshold_reached = {
                "seq_num": self.global_seq_num,
                "state_ref": {"state_machine_id": ctx.machine_id, "state_id": ctx.state_id,
                              "paused": False},
                "sub_state": {
                    "playback_speed": 1, "position": 30012, "duration": times,
                    "media_type": "AUDIO", "bitrate": audio_quality, "audio_quality": "HIGH",
                    "format": 10
                },
                "previous_position": 30012,
                "debug_source": "played_threshold_reached",
            }
            requests.put(URL_STATE, headers=HEADERS_BASE, json=played_threshold_reached)

            self.global_seq_num += 1
            before_load_payload = {
                "seq_num": self.global_seq_num,
                "state_ref": {
                    "state_machine_id": next_machine_id,
                    "state_id": next_playback_id,
                    "paused": True
                },
                "sub_state": {
                    "playback_speed": 0, "position": 0, "duration": times,
                    "media_type": "AUDIO", "bitrate": audio_quality, "audio_quality": "HIGH",
                    "format": 10, "is_video_on": False
                },
                "previous_position": times,
                "debug_source": "before_track_load"
            }
            requests.put(URL_STATE, headers=HEADERS_BASE, json=before_load_payload)

            self.global_seq_num += 1
            final_state_payload = {
                "seq_num": self.global_seq_num,
                "state_ref": {
                    "state_machine_id": ctx.machine_id,
                    "state_id": ctx.state_id,
                    "paused": True
                },
                "sub_state": {
                    "playback_speed": 0, "position": 30016, "duration": times,
                    "media_type": "AUDIO", "bitrate": audio_quality, "audio_quality": "HIGH",
                    "format": 10, "is_video_on": False
                },
                "previous_position": 30016,
                "playback_stats": {
                    "ms_total_est": times, "ms_metadata_duration": 0, "ms_manifest_latency": 0,
                    "ms_latency": 143, "ms_first_bytes_latency": 612, "start_offset_ms": 30000,
                    "ms_initial_buffering": 141, "ms_initial_rebuffer": 141, "ms_seek_rebuffering": 0,
                    "ms_stalled": 0, "max_ms_seek_rebuffering": 0, "max_ms_stalled": 0, "n_stalls": 0,
                    "n_rendition_upgrade": 0, "n_rendition_downgrade": 0, "bps_bandwidth_max": 0,
                    "bps_bandwidth_min": 0, "bps_bandwidth_avg": 0, "audiocodec": "mp4",
                    "audio_start_bitrate": audio_quality, "video_start_bitrate": None, "start_bitrate": audio_quality,
                    "time_weighted_bitrate": 0, "key_system": "widevine", "ms_key_latency": 594,
                    "total_bytes": 496099, "local_time_ms": current_time_ms, "n_dropped_video_frames": 0,
                    "n_total_video_frames": 0, "resolution_max": 0, "resolution_min": 0, "strategy": "MSE",
                    "ms_played_per_surface": {}, "ms_played_visible": 0,
                    "ms_played_per_audio_format": {f"mp4a.40.2;{audio_quality}": 16}, "ms_played_per_video_format": {}
                },
                "debug_source": "track_data_finalized"
            }
            requests.put(URL_STATE, headers=HEADERS_BASE, json=final_state_payload)


            json_data_str = json.dumps({
                "track": {"uri": track_uri, "playableURI": track_uri, "fileId": ctx.file_id,
                          "resolvedURL": None,
                          "contentType": "music", "playable": True, "isAd": False, "format": "MP4",
                          "fileFormat": 10, "mediaType": "audio", "noManifest": False,
                          "metadata": {"playbackQuality": "HIGH", "hifiStatus": "NONE"},
                          "options": {"position": 30000, "paused": False, "playedThreshold": 30000,
                                      "useDefaultPlaybackSpeed": True, "playbackSpeed": 1,
                                      "mediaPlaybackMode": "audio"},
                          "logData": {"noLog": False, "noTSV": False, "deviceId": local_device_id,
                                      "playbackId": next_playback_id, "reason": "remote",
                                      "displayTrack": track_uri,
                                      "playContext": track_uri, "impressionURLs": None,
                                      "format": {"codec": "MP4", "bitrate": audio_quality}, "uriType": "track",
                                      "displayTitle": "Unknown", "displayGroup": "Unknown",
                                      "displayDuration": 234466, "playbackService": "track-playback"},
                          "stateId": next_playback_id, "audioGain": -8.0},
                "event_position": 30000, "prev_position": 30000, "curr_position": 30000
            })

            client_events_payload = {
                "messages": [
                    {"type": "client_event",
                     "message": {"source": "harmony:track_playback:client", "context": "unknown",
                                 "event": "position_changed", "event_version": "1.0.0", "test_version": "",
                                 "source_version": "4.64.0-63a650210", "source_vendor": "spotify",
                                 "json_data": json_data_str}},
                    {"type": "client_event",
                     "message": {"source": "harmony:track_playback:client", "context": "unknown",
                                 "event": "position_changed - same position as previous event",
                                 "event_version": "1.0.0", "test_version": "",
                                 "source_version": "4.64.0-63a650210",
                                 "source_vendor": "spotify", "json_data": json_data_str}}
                ],
                "sdk_id": "harmony:4.64.0-63a650210",
                "platform": "web_player windows 10;chrome 117.0.0.0;desktop",
                "client_version": "0.0.0"
            }
            requests.post(URL_TELEMETRY, headers=telemetry_headers, data=json.dumps(client_events_payload))

        except Exception as e:
            print(f"{e}")
        ctx.stop_event.set()
        if ctx.ws_client:
            ctx.ws_client.close()


    def get_lyrics(self, track_id: str) -> dict | None:
        self._refresh_session_auth()
        response = self.session.get(self.LYRICS_API_URL.format(track_id=track_id))
        if response.status_code == 404:
            return None
        check_response(response)
        return response.json()

    def extract_keys_with_cdrm(self, pssh, media_type):
        cmd = self.session.post('https://cdrm-project.com/api/decrypt',
            headers={'Accept': 'application/json',
                     'Content-Type': 'application/json'},
            json={
                  'pssh': pssh,
                  'licurl': self.WIDEVINE_LICENSE_API_URL.format(type=media_type),
                  'headers': str(self.session.headers)
            }).json()
        return cmd['message']

    def get_track(self, track_id: str) -> dict:
        self._refresh_session_auth()
        payload = {
            "variables": {
                "uri": f"spotify:track:{track_id}"
            },
            "operationName": "getTrack",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "612585ae06ba435ad26369870deaae23b5c8800a256cd8a57e08eddc25a37294"
                }
            }
        }

        response = self.session.post(
            self.METADATA_API_URL,
            json=payload,
        )
        check_response(response)
        return response.json()

    def extended_media_collection(
        self,
        next_url: str,
    ) -> typing.Generator[dict, None, None]:
        while next_url is not None:
            response = self.session.get(next_url)
            check_response(response)
            extended_collection = response.json()
            yield extended_collection
            next_url = extended_collection["next"]
            time.sleep(self.EXTEND_TRACK_COLLECTION_WAIT_TIME)

    @functools.lru_cache()

    def get_album(
        self,
        album_id: str,
        extend: bool = True,
    ) -> dict:
        payload = {
            "variables": {
                "uri": f"spotify:album:{album_id}", "locale": "intl-pt", "offset": 0, "limit": 5000
            },
            "operationName": "getAlbum",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "b9bfabef66ed756e5e13f68a942deb60bd4125ec1f1be8cc42769dc0259b4b10"
                }
            }
        }

        response = self.session.post(
            self.METADATA_API_URL,
            json=payload,
        )

        return response.json()['data']['albumUnion']['tracksV2']['items']


    def get_playlist(
        self,
        playlist_id: str,
        extend: bool = True,
    ) -> dict:
        self._refresh_session_auth()
        payload = {
            "variables": {
                "uri": f"spotify:playlist:{playlist_id}",
                "offset": 0,
                "limit": 5000,
                "enableWatchFeedEntrypoint": True
            },
            "operationName": "fetchPlaylist",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "bb67e0af06e8d6f52b531f97468ee4acd44cd0f82b988e15c2ea47b1148efc77"
                }
            }
        }

        response = self.session.post(
            self.METADATA_API_URL,
            json=payload,
        )
        return response.json()['data']['playlistV2']


    def get_track_credits(self, track_id: str) -> dict:
        self._refresh_session_auth()
        response = self.session.get(
            self.TRACK_CREDITS_API_URL.format(track_id=track_id)
        )
        check_response(response)
        return response.json()

    def get_episode(self, episode_id: str) -> dict:
        self._refresh_session_auth()
        payload = {
            "variables": {
                "uri": f"spotify:episode:{episode_id}"
            },
            "operationName": "getEpisodeOrChapter",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "8a62dbdeb7bd79605d7d68b01bcdf83f08bc6c6287ee1665ba012c748a4cf1f3"
                }
            }
        }

        response = self.session.post(
            self.METADATA_API_URL,
            json=payload,
        )
        check_response(response)
        return response.json()['data']['episodeUnionV2']

    def get_show(self, show_id: str, extend: bool = True) -> dict:
        self._refresh_session_auth()
        payload = {
            "variables": {
                "uri": f"spotify:show:{show_id}",
                "offset": 0,
                "limit": 5000
            },
            "operationName": "queryPodcastEpisodes",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "8e2826c5993383566cc08bf9f5d3301b69513c3f6acb8d706286855e57bf44b2"
                }
            }
        }
        response = self.session.post(
            self.METADATA_API_URL,
            json=payload,
        )
        check_response(response)
        show = response.json()
        '''if extend:
            show["episodes"]["items"].extend(
                [
                    item
                    for extended_collection in self.extended_media_collection(
                        show["episodes"]["next"],
                    )
                    for item in extended_collection["items"]
                ]
            )'''
        return show["data"]['podcastUnionV2']

    def get_artist_albums_selection(
        self,
        artist_id: str,
        extend: bool = True,
    ) -> dict:
        self._refresh_session_auth()
        payload = {
            "variables": {
                "uri": f"spotify:artist:{artist_id}",
                "offset": 0,
                "limit": 5000,
                "order": "DATE_DESC"
            },
            "operationName": "queryArtistDiscographyAlbums",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "5e07d323febb57b4a56a42abbf781490e58764aa45feb6e3dc0591564fc56599"
                }
            }
        }
        response = self.session.post(self.METADATA_API_URL, json=payload)
        check_response(response)
        artist_albums = response.json()['data']['artistUnion']['discography']['albums']
        return self._select_and_queue(artist_albums, "Albuns")

    def get_artist_singles_selection(
        self,
        artist_id: str,
        extend: bool = True,
    ) -> dict:
        self._refresh_session_auth()
        payload = {
            "variables": {
                "uri": f"spotify:artist:{artist_id}",
                "offset": 0,
                "limit": 5000,
                "order": "DATE_DESC"
            },
            "operationName": "queryArtistDiscographySingles",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "5e07d323febb57b4a56a42abbf781490e58764aa45feb6e3dc0591564fc56599"
                }
            }
        }
        response = self.session.post(self.METADATA_API_URL, json=payload)
        check_response(response)
        artist_albums = response.json()['data']['artistUnion']['discography']['singles']
        return self._select_and_queue(artist_albums, "Singles")

    def get_artist_compilations_selection(
        self,
        artist_id: str,
        extend: bool = True,
    ) -> dict:
        self._refresh_session_auth()
        payload = {
            "variables": {
                "uri": f"spotify:artist:{artist_id}",
                "offset": 0,
                "limit": 5000,
                "order": "DATE_DESC"
            },
            "operationName": "queryArtistDiscographyCompilations",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "5e07d323febb57b4a56a42abbf781490e58764aa45feb6e3dc0591564fc56599"
                }
            }
        }
        response = self.session.post(self.METADATA_API_URL, json=payload)
        check_response(response)
        artist_albums = response.json()['data']['artistUnion']['discography']['compilations']
        return self._select_and_queue(artist_albums, "Compilations")

    def get_artist_collaborations_selection(
        self,
        artist_id: str,
        extend: bool = True,
    ) -> dict:
        self._refresh_session_auth()
        payload = {
            "variables": {
                "uri": f"spotify:artist:{artist_id}",
                "offset": 0,
                "limit": 5000,
                "order": "DATE_DESC"
            },
            "operationName": "queryArtistAppearsOn",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "9a4bb7a20d6720fe52d7b47bc001cfa91940ddf5e7113761460b4a288d18a4c1"
                }
            }
        }
        response = self.session.post(self.METADATA_API_URL, json=payload)
        check_response(response)
        artist_albums = response.json()['data']['artistUnion']['relatedContent']['appearsOn']
        return self._select_and_queue(artist_albums, "Collaborations")

    def _select_and_queue(self, data_input: any, category_name: str) -> list[str]:
        raw_items = []
        if isinstance(data_input, dict) and 'items' in data_input:
            raw_items = data_input['items']
        elif isinstance(data_input, list):
            raw_items = data_input

        if not raw_items:
            print(f"No {category_name} found for this artist.")
            return []

        clean_list = []
        for entry in raw_items:
            try:
                if 'releases' in entry and 'items' in entry['releases']:
                    album_data = entry['releases']['items'][0]
                    clean_obj = {
                        'name': album_data.get('name', 'Unknown'),
                        'id': album_data.get('id'),
                        'year': str(album_data.get('date', {}).get('year', '????')),
                        'total_tracks': album_data.get('tracks', {}).get('totalCount', 0)
                    }
                    clean_list.append(clean_obj)
                elif 'name' in entry:
                    clean_list.append({
                        'name': entry.get('name'),
                        'id': entry.get('id'),
                        'year': entry.get('release_date', '????')[:4],
                        'total_tracks': entry.get('total_tracks', 0)
                    })
            except Exception:
                continue

        if not clean_list:
            print(f"Could not parse items for {category_name}.")
            return []

        print(f"\n--- Select {category_name} ---")
        print("Index | Tracks | Year | Name")
        for index, album in enumerate(clean_list):
            display_str = f"{album['total_tracks']:03d} | {album['year']} | {album['name']}"
            print(f"[{index + 1}] {display_str}")

        print("\nType numbers separated by space (e.g. '1 3') or 'all'.")
        user_input = input("Selection: ").strip().lower()

        selected_ids = []

        if user_input == 'all':
            selected_ids = [album['id'] for album in clean_list]
        else:
            parts = user_input.replace(',', ' ').split()
            for part in parts:
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(clean_list):
                        selected_ids.append(clean_list[idx]['id'])

        return selected_ids


    def get_video_manifest(
        self,
        gid: str,
    ) -> dict:
        self._refresh_session_auth()
        response = self.session.get(self.VIDEO_MANIFEST_API_URL.format(gid=gid))
        check_response(response)
        return response.json()

    def get_seek_table(self, file_id: str) -> dict:
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Origin": self.SPOTIFY_HOME_PAGE_URL,
            "Pragma": "no-cache",
            "Priority": "u=4",
            "Referer": self.SPOTIFY_HOME_PAGE_URL,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
            "User-Agent": self.session.headers["user-agent"],
        }
        response = requests.get(
            self.SEEK_TABLE_API_URL.format(file_id=file_id),
            headers=headers,
        )
        check_response(response)
        return response.json()

    def get_playplay_license(self, file_id: str, challenge: bytes) -> bytes:
        self._refresh_session_auth()
        response = self.session.post(
            self.PLAYPLAY_LICENSE_API_URL.format(file_id=file_id),
            challenge,
        )
        check_response(response)
        return response.content

    def get_widevine_license(self, challenge: bytes, media_type: str) -> bytes:
        self._refresh_session_auth()
        response = self.session.post(
            self.WIDEVINE_LICENSE_API_URL.format(type=media_type),
            challenge,
        )
        if response.status_code == 403:
            logger.error(f"The device.wvd file is invalid or banned.")
            logger.warning(f'Delete the device.wvd file to use the alternate key.')
        check_response(response)
        return response.content

    def get_stream_urls(self, file_id: str) -> str:
        self._refresh_session_auth()
        response = self.session.get(self.STREAM_URLS_API_URL.format(file_id=file_id))
        check_response(response)
        return response.json()

    def get_now_playing_view(self, track_id: str, artist_id: str) -> dict:
        self._refresh_session_auth()
        response = self.session.get(
            self.PATHFINDER_API_URL,
            params={
                "operationName": "queryNpvArtist",
                "variables": json.dumps(
                    {
                        "artistUri": f"spotify:artist:{artist_id}",
                        "trackUri": f"spotify:track:{track_id}",
                        "enableCredits": True,
                        "enableRelatedVideos": True,
                    }
                ),
                "extensions": json.dumps(
                    {
                        "persistedQuery": {
                            "version": 1,
                            "sha256Hash": "4ec4ae302c609a517cab6b8868f601cd3457c751c570ab12e988723cc036284f",
                        }
                    }
                ),
            },
        )
        check_response(response)
        return response.json()
