# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import signal
import datetime
from prettytable import NONE
from prettytable import FRAME
from prettytable import PrettyTable

try:
    import simdjson as json
except:
    try:
        import ujson as json
    except:
        import json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import trash
from otpme.lib import stuff
#from otpme.lib import cache
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import locking
from otpme.lib import filetools
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.clusterd import calc_node_vote
from otpme.lib.protocols.otpme_server import OTPmeServer1
from otpme.lib.freeradius.utils import reload as freeradius_reload

from otpme.lib.exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-cluster-1.0"

def register():
    config.register_otpme_protocol("clusterd", PROTOCOL_VERSION, server=True)

class OTPmeClusterP1(OTPmeServer1):
    """ Class that implements OTPme-cluster-1.0. """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "clusterd"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Indicates parent class that we need no authentication.
        self.require_auth = "host"
        self.require_preauth = False
        self.require_client_cert = True
        self.encrypt_session = True
        self.require_master_node = False
        self.require_cluster_status = False
        self.compresss_response = False
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def signal_handler(self, _signal, frame):
        """ Handle signals """
        if _signal != 15:
            return
        for lock in multiprocessing.cluster_write_locks:
            lock.release_lock()
        for lock in multiprocessing.cluster_read_locks:
            lock.release_lock()
        OTPmeServer1.signal_handler(self, _signal, frame)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    def _preauth_check(self, preauth_args):
        """ Do preauth check. """
        # Try to cluster key.
        try:
            cluster_key = preauth_args['cluster_key']
        except:
            msg = _("Missing cluster key.")
            raise OTPmeException(msg)
        own_site = backend.get_object(uuid=config.site_uuid)
        if own_site.cluster_key == cluster_key:
            return
        msg = _("Received invalid cluster key.")
        raise OTPmeException(msg)

    def get_running_jobs(self):
        running_jobs = dict(multiprocessing.running_jobs)
        if len(running_jobs) == 0:
            return
        table_headers = ['Start Time', 'Job Name', 'Auth Token', 'PID']
        table = PrettyTable(table_headers,
                            header_style="title",
                            vrules=NONE,
                            hrules=FRAME)
        job_added = False
        table.align = "l"
        table.padding_width = 0
        table.right_padding_width = 1
        for x in running_jobs:
            x_name = running_jobs[x]['name']
            x_pid = running_jobs[x]['pid']
            if x_pid:
                if not stuff.check_pid(x_pid):
                    continue
            x_start_time = running_jobs[x]['start_time']
            x_start_time = datetime.datetime.fromtimestamp(x_start_time)
            try:
                x_auth_token = running_jobs[x]['auth_token']
            except KeyError:
                x_auth_token = None
            row = [x_start_time, x_name, x_auth_token, x_pid]
            table.add_row(row)
            job_added = True
        if not job_added:
            return
        # Get output string from table.
        output = table.get_string(start=0)
        return output

    def verify_peer(self):
        """ Verify peer. """
        if self.peer.type != "node":
            msg = _("Peer is not a node.")
            raise OTPmeException(msg)
        if self.peer.realm != config.realm:
            msg = _("Peer is not from our realm: {realm}")
            msg = msg.format(realm=self.peer.realm)
            raise OTPmeException(msg)
        if self.peer.site != config.site:
            msg = _("Peer is not from our site: {site}")
            msg = msg.format(site=self.peer.site)
            raise OTPmeException(msg)
        if not self.peer.enabled:
            msg = _("Peer is disabled: {name}")
            msg = msg.format(name=self.peer.name)
            raise HostDisabled(msg)

    def _process(self, command, command_args, **kwargs):
        """ Handle commands received from host_handler. """
        # All valid commands.
        valid_commands = [
                            "ping",
                            "sync",
                            "write",
                            "rename",
                            "delete",
                            "trash_write",
                            "trash_empty",
                            "trash_delete",
                            "sync_trash",
                            "acquire_lock",
                            "release_lock",
                            "get_checksums",
                            "get_full_checksums",
                            "get_index_checksums",
                            "object_exists",
                            "get_node_vote",
                            "get_last_used",
                            "set_node_sync",
                            "last_used_write",
                            "unset_node_sync",
                            "set_node_online",
                            "get_master_node",
                            "do_radius_reload",
                            "do_nsscache_sync",
                            "do_daemon_reload",
                            "get_member_nodes",
                            "get_data_revision",
                            "do_master_failover",
                            "get_cluster_quorum",
                            "get_cluster_status",
                            "set_required_votes",
                            "set_master_failover",
                            "get_node_sync_status",
                            "start_master_failover",
                            "get_master_sync_status",
                            "deconfigure_floating_ip",
                            "get_master_failover_status",
                        ]

        # Make sure peer is a node from our site.
        try:
            self.verify_peer()
        except HostDisabled as e:
            status = status_codes.HOST_DISABLED
            message = _("Failed to verify peer: {peer}: {error}")
            message = message.format(peer=self.peer, error=e)
            response = self.build_response(status, message, encrypt=False)
            return response
        except Exception as e:
            status = False
            message = _("Failed to verify peer: {peer}: {error}")
            message = message.format(peer=self.peer, error=e)
            response = self.build_response(status, message, encrypt=False)
            return response

        # Check if we got a valid command
        if not command in valid_commands:
            log_msg = _("Received unknown command {cmd} from client: {client}", log=True)[1]
            log_msg = log_msg.format(cmd=command, client=self.client)
            logger.warning(log_msg)
            message = _("Unknown command: {cmd}")
            message = message.format(cmd=command)
            status = False

        elif command == "ping":
            message = _("pong")
            status = True
            log_msg = _("Received ping.", log=True)[1]
            logger.debug(log_msg)

        elif command == "get_data_revision":
            status = True
            message = config.get_data_revision()

        elif command == "get_master_node":
            try:
                message = multiprocessing.master_node['master']
                status = True
            except KeyError:
                message = None
                status = False

        elif command == "get_cluster_status":
            status = True
            message = config.cluster_status

        elif command == "get_cluster_quorum":
            status = True
            try:
                cluster_quorum = config.cluster_quorum
            except:
                cluster_quorum = False
            message = cluster_quorum
            if cluster_quorum:
                try:
                    message = multiprocessing.cluster_quorum['quorum']
                except KeyError:
                    message = cluster_quorum

        elif command == "set_required_votes":
            status = True
            try:
                required_votes = command_args['required_votes']
            except KeyError:
                message = _("Missing requied votes.")
                status = False
            try:
                required_votes = int(required_votes)
            except ValueError:
                message = _("Need <required_votes> as int.")
                status = False
            if status:
                own_site = backend.get_object(uuid=config.site_uuid)
                if own_site.required_votes != required_votes:
                    message = _("Required votes set.")
                    own_site.required_votes = required_votes
                    own_site._write(cluster=True, wait_for_cluster_writes=False)
                else:
                    message = _("Required votes already set to {votes}.")
                    message = message.format(votes=required_votes)
                    status = False

        elif command == "get_master_sync_status":
            if config.host_data['name'] in multiprocessing.master_sync_done:
                status = True
                message = _("Master sync done.")
            else:
                status = False
                message = _("Master sync not done.")

        elif command == "get_node_sync_status":
            if os.path.exists(config.node_sync_file):
                status = True
                message = _("Node in sync.")
            else:
                status = False
                message = _("Node not in sync.")

        elif command == "set_node_online":
            status = True
            message = _("Node online.")
            multiprocessing.online_nodes[self.peer.name] = True

        elif command == "set_node_sync":
            status = True
            message = _("Node in sync.")
            if not config.master_failover:
                sync_time = command_args['sync_time']
                config.touch_node_sync_file(sync_time)

        elif command == "unset_node_sync":
            status = True
            message = _("Node NOT in sync.")
            config.remove_node_sync_file()

        elif command == "get_node_vote":
            status = True
            message = 0.0
            # Get/set vote for this node. This is also done in clusterd daemon.
            if config.cluster_vote_participation:
                message = calc_node_vote()

        elif command == "get_member_nodes":
            status = True
            message = multiprocessing.member_nodes.keys()

        elif command == "get_checksums":
            status = True
            object_types = list(config.tree_object_types)
            data_types = list(config.flat_object_types)
            data_types.remove("session")
            session_types = ['session']
            object_checksums, objects_checksum = backend.get_sync_list(realm=config.realm,
                                                                    site=config.site,
                                                                    object_types=object_types)
            data_checksums, data_checksum = backend.get_sync_list(realm=config.realm,
                                                                site=config.site,
                                                                object_types=data_types)
            session_checksums, sessions_checksum = backend.get_sync_list(realm=config.realm,
                                                                        site=config.site,
                                                                        object_types=session_types)
            message = {
                        'object_checksums'  : object_checksums,
                        'objects_checksum'  : objects_checksum,
                        'data_checksum'     : data_checksum,
                        'data_checksums'    : data_checksums,
                        'sessions_checksum' : sessions_checksum,
                        'session_checksums' : session_checksums,
                        }

        elif command == "get_full_checksums":
            status = True
            object_types = list(config.tree_object_types)
            data_types = list(config.flat_object_types)
            data_types.remove("session")
            session_types = ['session']

            object_checksums = {}
            for object_type in object_types:
                result = backend.search(object_type=object_type,
                                        realm=config.realm,
                                        site=config.site,
                                        attribute="uuid",
                                        value="*",
                                        return_type="oid")
                for x_oid in result:
                    oc = backend.read_config(x_oid)
                    if not oc:
                        continue
                    oc.update_checksums(force=True)
                    object_checksums[x_oid.full_oid] = oc.checksum
            objects_checksum = json.dumps(object_checksums, sort_keys=True)
            objects_checksum = stuff.gen_md5(objects_checksum)

            data_checksums = {}
            for object_type in data_types:
                result = backend.search(object_type=object_type,
                                        realm=config.realm,
                                        site=config.site,
                                        attribute="uuid",
                                        value="*",
                                        return_type="oid")
                for x_oid in result:
                    oc = backend.read_config(x_oid)
                    if not oc:
                        continue
                    oc.update_checksums(force=True)
                    data_checksums[x_oid.full_oid] = oc.checksum
            data_checksum = json.dumps(data_checksums, sort_keys=True)
            data_checksum = stuff.gen_md5(data_checksum)

            session_checksums = {}
            for object_type in session_types:
                result = backend.search(object_type=object_type,
                                        realm=config.realm,
                                        site=config.site,
                                        attribute="uuid",
                                        value="*",
                                        return_type="oid")
                for x_oid in result:
                    oc = backend.read_config(x_oid)
                    if not oc:
                        continue
                    oc.update_checksums(force=True)
                    session_checksums[x_oid.full_oid] = oc.checksum
            sessions_checksum = json.dumps(session_checksums, sort_keys=True)
            sessions_checksum = stuff.gen_md5(sessions_checksum)

            message = {
                        'object_checksums'  : object_checksums,
                        'objects_checksum'  : objects_checksum,
                        'data_checksum'     : data_checksum,
                        'data_checksums'    : data_checksums,
                        'sessions_checksum' : sessions_checksum,
                        'session_checksums' : session_checksums,
                        }

        elif command == "get_index_checksums":
            status = True
            object_types = list(config.tree_object_types)
            data_types = list(config.flat_object_types)
            data_types.remove("session")
            session_types = ['session']

            object_checksums = {}
            for object_type in object_types:
                result = backend.search(object_type=object_type,
                                        realm=config.realm,
                                        site=config.site,
                                        attribute="uuid",
                                        value="*",
                                        return_type="oid")
                for x_oid in result:
                    index_dump = backend.index_dump(object_id=x_oid,
                                                    checksum_ready=True)
                    index_dump = json.dumps(index_dump, sort_keys=True)
                    index_checksum = stuff.gen_md5(index_dump)
                    object_checksums[x_oid.full_oid] = index_checksum
            objects_checksum = json.dumps(object_checksums, sort_keys=True)
            objects_checksum = stuff.gen_md5(objects_checksum)

            data_checksums = {}
            for object_type in data_types:
                result = backend.search(object_type=object_type,
                                        realm=config.realm,
                                        site=config.site,
                                        attribute="uuid",
                                        value="*",
                                        return_type="oid")
                for x_oid in result:
                    index_dump = backend.index_dump(object_id=x_oid,
                                                    checksum_ready=True)
                    index_dump = json.dumps(index_dump, sort_keys=True)
                    index_checksum = stuff.gen_md5(index_dump)
                    data_checksums[x_oid.full_oid] = index_checksum
            data_checksum = json.dumps(data_checksums, sort_keys=True)
            data_checksum = stuff.gen_md5(data_checksum)

            session_checksums = {}
            for object_type in session_types:
                result = backend.search(object_type=object_type,
                                        realm=config.realm,
                                        site=config.site,
                                        attribute="uuid",
                                        value="*",
                                        return_type="oid")
                for x_oid in result:
                    index_dump = backend.index_dump(object_id=x_oid,
                                                    checksum_ready=True)
                    index_dump = json.dumps(index_dump, sort_keys=True)
                    index_checksum = stuff.gen_md5(index_dump)
                    session_checksums[x_oid.full_oid] = index_checksum
            sessions_checksum = json.dumps(session_checksums, sort_keys=True)
            sessions_checksum = stuff.gen_md5(sessions_checksum)

            message = {
                        'object_checksums'  : object_checksums,
                        'objects_checksum'  : objects_checksum,
                        'data_checksum'     : data_checksum,
                        'data_checksums'    : data_checksums,
                        'sessions_checksum' : sessions_checksum,
                        'session_checksums' : session_checksums,
                        }

        elif command == "sync":
            status = True
            message = None
            try:
                remote_objects = command_args['remote_objects']
            except:
                message = _("Missing remote objects.")
                status = False
            if status:
                object_types = config.get_cluster_object_types()
                return_attributes = ['oid', 'sync_checksum']
                result = backend.search(object_types=object_types,
                                        attribute="uuid",
                                        value="*",
                                        return_attributes=return_attributes)
                sync_objects = {}
                sync_objects_count = 0
                for x_uuid in result:
                    x_oid = result[x_uuid]['oid']
                    x_checksum = result[x_uuid]['sync_checksum']
                    sync_object = False
                    try:
                        remote_object_data = remote_objects[x_oid.full_oid]
                    except KeyError:
                        remote_object_data = None
                        sync_object = True
                    if remote_object_data:
                        remote_checksum = remote_object_data['sync_checksum']
                        if remote_checksum != x_checksum:
                            sync_object = True
                    if not sync_object:
                        sync_objects[x_oid.full_oid] = None
                        continue
                    x_object_config = backend.read_config(x_oid)
                    if not x_object_config:
                        continue
                    x_object_config = x_object_config.copy()
                    x_sync_checksum = backend.get_sync_checksum(x_oid)
                    x_object_config['SYNC_CHECKSUM'] = x_sync_checksum
                    sync_objects_count += 1
                    sync_objects[x_oid.full_oid] = {}
                    sync_objects[x_oid.full_oid]['object_config'] = x_object_config
                message = sync_objects
                log_msg = _("Sending {count} objects to peer: {peer}", log=True)[1]
                log_msg = log_msg.format(count=sync_objects_count, peer=self.peer.name)
                logger.info(log_msg)

        elif command == "sync_trash":
            status = True
            message = None
            try:
                remote_objects = command_args['remote_objects']
            except:
                message = _("Missing remote objects.")
                status = False
            if status:
                local_objects = trash.get_trash_data()
                sync_objects = {}
                sync_objects_count = 0
                for x_trash_id in local_objects:
                    x_deleted_by = trash.get_deleted_by(x_trash_id)
                    for x_oid in local_objects[x_trash_id]:
                        if x_oid == trash.DELETED_BY_FILENAME:
                            continue
                        add_trash = False
                        if x_trash_id not in remote_objects:
                            add_trash = True
                        else:
                            if x_oid not in remote_objects[x_trash_id]:
                                add_trash = True
                        if not add_trash:
                            continue
                        if x_trash_id not in sync_objects:
                            sync_objects[x_trash_id] = {}
                        x_object_data = trash.read_entry(x_trash_id, x_oid)
                        sync_objects[x_trash_id][x_oid] = {}
                        sync_objects[x_trash_id][x_oid]['deleted_by'] = x_deleted_by
                        sync_objects[x_trash_id][x_oid]['object_data'] = x_object_data
                        sync_objects_count += 1
                    if x_trash_id not in sync_objects:
                        sync_objects[x_trash_id] = None
                message = sync_objects
                log_msg = _("Sending {count} trash objects to peer: {peer}", log=True)[1]
                log_msg = log_msg.format(count=sync_objects_count, peer=self.peer.name)
                logger.info(log_msg)

        elif command == "object_exists":
            status = True
            message = None
            try:
                object_id = command_args['object_id']
            except:
                message = _("Missing object ID.")
                status = False
            if status:
                object_id = oid.get(object_id)
                message = backend.object_exists(object_id)

        elif command == "write":
            status = True
            message = None
            try:
                object_id = command_args['object_id']
            except:
                message = _("Missing object ID.")
                status = False
            try:
                object_uuid = command_args['object_uuid']
            except:
                message = _("Missing object UUID.")
                status = False
            try:
                object_config = command_args['object_config']
            except:
                message = _("Missing object config.")
                status = False
            try:
                acl_journal = command_args['acl_journal']
            except:
                message = _("Missing ACL journal.")
                status = False
            try:
                ldif_journal = command_args['ldif_journal']
            except:
                message = _("Missing LDIF journal.")
                status = False
            try:
                index_journal = command_args['index_journal']
            except:
                message = _("Missing index journal.")
                status = False
            try:
                use_acl_journal = command_args['use_acl_journal']
            except:
                message = _("Missing use_acl_journal.")
                status = False
            try:
                use_index_journal = command_args['use_index_journal']
            except:
                message = _("Missing use_index_journal.")
                status = False
            try:
                full_data_update = command_args['full_data_update']
            except:
                full_data_update = False
            try:
                full_index_update = command_args['full_index_update']
            except:
                full_index_update = False
            try:
                full_ldif_update = command_args['full_ldif_update']
            except:
                full_ldif_update = False
            try:
                full_acl_update = command_args['full_acl_update']
            except:
                full_acl_update = False
            try:
                last_used = command_args['last_used']
            except:
                last_used = None
            if config.daemon_shutdown:
                message = _("Daemon shutdown.")
                status = False
            if status:
                object_id = oid.get(object_id)
                checksum = object_config['CHECKSUM']
                log_msg = _("Writing object: {id} ({checksum})", log=True)[1]
                log_msg = log_msg.format(id=object_id, checksum=checksum)
                logger.debug(log_msg)
                message = "done"
                try:
                    backend.write_config(object_id=object_id,
                                        cluster=False,
                                        full_data_update=full_data_update,
                                        full_index_update=full_index_update,
                                        full_ldif_update=full_ldif_update,
                                        full_acl_update=full_acl_update,
                                        index_journal=index_journal,
                                        use_index_journal=use_index_journal,
                                        ldif_journal=ldif_journal,
                                        acl_journal=acl_journal,
                                        use_acl_journal=use_acl_journal,
                                        object_config=object_config)
                except Exception as e:
                    status = False
                    log_msg = _("Failed to write object: {id}: {error}", log=True)[1]
                    log_msg = log_msg.format(id=object_id, error=e)
                    self.logger.warning(log_msg)

                if status:
                    if last_used:
                        backend.set_last_used(object_id.object_type,
                                            object_uuid,
                                            last_used, cluster=False)

                if status:
                    while True:
                        entry_time = str(time.time_ns())
                        cluster_journal_file = os.path.join(config.cluster_in_journal_dir, entry_time)
                        if os.path.exists(cluster_journal_file):
                            continue
                        break
                    object_data = {
                                    'action'            : 'write',
                                    'object_id'         : object_id.read_oid,
                                }
                    file_content = json.dumps(object_data)
                    try:
                        filetools.create_file(path=cluster_journal_file,
                                                content=file_content,
                                                compression="lz4")
                    except Exception as e:
                        message = _("Failed to write cluster journal: {id}: {file}: {error}")
                        message = message.format(id=object_id, file=cluster_journal_file, error=e)
                        status = False
                    else:
                        multiprocessing.cluster_in_event.set()
                        message = "done"

        elif command == "rename":
            status = True
            message = None
            try:
                object_id = command_args['object_id']
            except:
                message = _("Missing object ID.")
                status = False
            try:
                new_object_id = command_args['new_object_id']
            except:
                message = _("Missing new object ID.")
                status = False
            if config.daemon_shutdown:
                message = _("Daemon shutdown.")
                status = False
            if status:
                object_id = oid.get(object_id)
                new_object_id = oid.get(new_object_id)
                our_object = backend.get_object(object_id)
                if our_object.oid.full_oid == object_id.full_oid:
                    log_msg = _("Renaming object: {old_id}: {new_id}", log=True)[1]
                    log_msg = log_msg.format(old_id=object_id, new_id=new_object_id)
                    self.logger.debug(log_msg)
                    try:
                        backend.rename_object(object_id,
                                            new_object_id,
                                            cluster=False)
                    except Exception as e:
                        status = False
                        message = _("Failed to rename object: {id}")
                        message = message.format(id=object_id)
                        log_msg = _("Failed to rename object: {id}: {error}", log=True)[1]
                        log_msg = log_msg.format(id=object_id, error=e)
                        self.logger.warning(log_msg)
                    else:
                        message = "done"

        elif command == "delete":
            status = True
            message = "done"
            try:
                object_id = command_args['object_id']
            except:
                message = _("Missing object ID.")
                status = False
            try:
                object_uuid = command_args['object_uuid']
            except:
                message = _("Missing object UUID.")
                status = False
            if config.daemon_shutdown:
                message = _("Daemon shutdown.")
                status = False
            if status:
                object_id = oid.get(object_id)
                try:
                    backend.delete_object(object_id=object_id)
                except UnknownObject:
                    pass
                except Exception as e:
                    status = False
                    message = _("Failed to delete object: {id}")
                    message = message.format(id=object_id)
                    log_msg = _("Failed to delete object: {id}: {error}", log=True)[1]
                    log_msg = log_msg.format(id=object_id, error=e)
                    self.logger.warning(log_msg)
                else:
                    message = "done"
                    log_msg = _("Removed object: {id}", log=True)[1]
                    log_msg = log_msg.format(id=object_id)
                    self.logger.debug(log_msg)

                while True:
                    entry_time = str(time.time_ns())
                    cluster_journal_file = os.path.join(config.cluster_in_journal_dir, entry_time)
                    if os.path.exists(cluster_journal_file):
                        continue
                    break
                object_data = {
                                'action'        : 'delete',
                                'object_id'     : object_id.read_oid,
                                'object_uuid'   : object_uuid,
                            }
                file_content = json.dumps(object_data)
                try:
                    filetools.create_file(path=cluster_journal_file,
                                            content=file_content,
                                            compression="lz4")
                except Exception as e:
                    message = _("Failed to write cluster journal: {id}: {file}: {error}")
                    message = message.format(id=object_id, file=cluster_journal_file, error=e)
                    status = False
                else:
                    multiprocessing.cluster_in_event.set()
                    message = "done"

        elif command == "trash_write":
            status = True
            message = None
            try:
                trash_id = command_args['trash_id']
            except:
                message = _("Missing trash ID.")
                status = False
            try:
                object_id = command_args['object_id']
            except:
                message = _("Missing object ID.")
                status = False
            try:
                deleted_by = command_args['deleted_by']
            except:
                message = _("Missing deleted_by.")
                status = False
            try:
                object_data = command_args['object_data']
            except:
                message = _("Missing object data.")
                status = False
            try:
                object_data = json.loads(object_data)
            except Exception as e:
                message = _("Failed to load trash object data: {trash_id}: {object_id}: {error}")
                message = message.format(trash_id=trash_id, object_id=object_id, error=e)
                status = False
            if config.daemon_shutdown:
                message = _("Daemon shutdown.")
                status = False
            if status:
                message = "done"
                log_msg = _("Writing trash object: {object_id} ({trash_id})", log=True)[1]
                log_msg = log_msg.format(object_id=object_id, trash_id=trash_id)
                logger.debug(log_msg)
                try:
                    trash.write_entry(trash_id,
                                    object_id,
                                    object_data,
                                    deleted_by)
                except Exception as e:
                    message, log_msg = _("Failed to add trash entry: {object_id}: {trash_id}: {error}", log=True)
                    message = message.format(object_id=object_id, trash_id=trash_id, error=e)
                    log_msg = log_msg.format(object_id=object_id, trash_id=trash_id, error=e)
                    logger.warning(log_msg)
                    status = False

        elif command == "trash_delete":
            status = True
            message = None
            try:
                trash_id = command_args['trash_id']
            except:
                message = _("Missing trash ID.")
                status = False
            if config.daemon_shutdown:
                message = _("Daemon shutdown.")
                status = False
            if status:
                message = "done"
                log_msg = _("Deleting trash object: {trash_id}", log=True)[1]
                log_msg = log_msg.format(trash_id=trash_id)
                logger.debug(log_msg)
                try:
                    trash.delete(trash_id=trash_id, cluster=False)
                except Exception as e:
                    message, log_msg = _("Failed to delete trash entry: {trash_id}: {error}", log=True)
                    message = message.format(trash_id=trash_id, error=e)
                    log_msg = log_msg.format(trash_id=trash_id, error=e)
                    logger.warning(log_msg)
                    status = False

        elif command == "trash_empty":
            status = True
            message = None
            if config.daemon_shutdown:
                message = _("Daemon shutdown.")
                status = False
            if status:
                message = "done"
                try:
                    trash.empty(cluster=False)
                except Exception as e:
                    message, log_msg = _("Failed to empty trash: {error}", log=True)
                    message = message.format(error=e)
                    log_msg = log_msg.format(error=e)
                    logger.warning(log_msg)
                    status = False
                else:
                    log_msg = _("Trash emptied.", log=True)[1]
                    logger.debug(log_msg)

        elif command == "get_last_used":
            status = True
            message = None
            try:
                object_types = command_args['object_types']
            except:
                message = _("Missing object type.")
                status = False
            if config.daemon_shutdown:
                message = _("Daemon shutdown.")
                status = False
            if status:
                try:
                    message = backend.get_last_used_times(object_types=object_types)
                    status = True
                except Exception as e:
                    log_msg = _("Failed to get last used data from backend: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)
                    message = _("Failed to get last used data from backend.")
                    status = False

        elif command == "last_used_write":
            status = True
            message = None
            try:
                object_type = command_args['object_type']
            except:
                message = _("Missing object type.")
                status = False
            try:
                objects = command_args['objects']
            except:
                message = _("Missing objects.")
                status = False
            if config.daemon_shutdown:
                message = _("Daemon shutdown.")
                status = False
            if status:
                message = "done"
                try:
                    backend.set_last_used_times(object_type, objects)
                except Exception as e:
                    message = _("Failed to set last used times: {error}")
                    message = message.format(error=e)
                    status = False

        elif command == "acquire_lock":
            status = True
            message = "done"
            try:
                lock_type = command_args['lock_type']
            except:
                message = _("Missing lock type.")
                status = False
            try:
                lock_id = command_args['lock_id']
            except:
                message = _("Missing lock ID.")
                status = False
            try:
                write = command_args['write']
            except:
                message = _("Missing write lock flag.")
                status = False
            if write:
                if lock_id in multiprocessing.cluster_write_locks:
                    status = False
                    message = _("Write lock exits: {lock_id}")
                    message = message.format(lock_id=lock_id)
            else:
                if lock_id in multiprocessing.cluster_read_locks:
                    status = False
                    message = _("Read lock exits: {lock_id}")
                    message = message.format(lock_id=lock_id)
            if status:
                try:
                    lock = locking.acquire_lock(lock_type=lock_type,
                                                lock_id=lock_id,
                                                write=write,
                                                timeout=0)
                except LockWaitTimeout:
                    status = False
                    message = _("Failed to acquire lock.")
                else:
                    if write:
                        multiprocessing.cluster_write_locks[lock_id] = lock
                    else:
                        multiprocessing.cluster_read_locks[lock_id] = lock

        elif command == "release_lock":
            status = True
            message = "done"
            try:
                lock_id = command_args['lock_id']
            except:
                message = _("Missing lock ID.")
                status = False
            try:
                write = command_args['write']
            except:
                message = _("Missing lock ID.")
                status = False
            if status:
                if write:
                    try:
                        lock = multiprocessing.cluster_write_locks.pop(lock_id)
                    except KeyError:
                        status = False
                        message = _("Unknown write lock: {lock_id}")
                        message = message.format(lock_id=lock_id)
                else:
                    try:
                        lock = multiprocessing.cluster_read_locks.pop(lock_id)
                    except KeyError:
                        status = False
                        message = _("Unknown read lock: {lock_id}")
                        message = message.format(lock_id=lock_id)
                if status:
                    lock.release_lock()

        elif command == "deconfigure_floating_ip":
            status = True
            message = _("Floating IP deconfigured.")
            log_msg = _("Received request to deconfigure floating IP.", log=True)[1]
            logger.info(log_msg)
            try:
                self.comm_handler.send("controld", command="deconfigure_floating_ip")
            except Exception as e:
                status = False
                message = _("Failed to send deconfigure floating IP request.")
                log_msg = _("Failed to send deconfigure floating IP request: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                logger.critical(log_msg)

        elif command == "start_master_failover":
            missing_nodes = []
            member_nodes = multiprocessing.member_nodes.keys()
            online_nodes = multiprocessing.online_nodes.keys()
            for node_name in online_nodes:
                if node_name in member_nodes:
                    continue
                missing_nodes.append(node_name)
            if missing_nodes:
                status = False
                missing_nodes = " ".join(missing_nodes)
                message = _("Waiting for node(s) to join cluster: {nodes}")
                message = message.format(nodes=missing_nodes)
            else:
                running_jobs = self.get_running_jobs()
                if running_jobs:
                    status = False
                    message = _("Cannot do master failover because of running jobs")
                    message = f"{message}\n{running_jobs}"
                else:
                    status = True
                    message = _("Master failover started.")
                    config.master_failover = True
                    time.sleep(3)
                    running_jobs = self.get_running_jobs()
                    if running_jobs:
                        status = False
                        config.master_failover = False
                        message = _("Cannot do master failover because of running jobs")
                        message = f"{message}\n{running_jobs}"

        elif command == "set_master_failover":
            status = True
            message = _("Master failover started successful.")
            config.cluster_status = False
            config.master_failover = True

        elif command == "get_master_failover_status":
            message = _("Master failover status.")
            status = config.master_failover

        elif command == "do_nsscache_sync":
            from otpme.lib.classes.command_handler import CommandHandler
            # Get command handler.
            command_handler = CommandHandler(interactive=False)
            # Add sync sites command to queue.
            try:
                command_handler.start_sync(sync_type="nsscache")
                status = True
                message = _("Nsscache sync queued.")
            except Exception as e:
                message, log_msg = _("Error queueing sync nsscache command: {error}", log=True)
                message = message.format(error=e)
                log_msg = log_msg.format(error=e)
                logger.warning(log_msg)
                status = True
            else:
                log_msg = _("nsscache sync queued.", log=True)[1]
                logger.info(log_msg)

        elif command == "do_radius_reload":
            try:
                freeradius_reload()
                status = True
                message = _("Radius reload done.")
            except Exception as e:
                message = _("Radius reload failed: {error}")
                message = message.format(error=e)
                status = False
            else:
                log_msg = _("Freeradius reloaded.", log=True)[1]
                logger.info(log_msg)

        elif command == "do_daemon_reload":
            # Reload e.g. after adding new CRL.
            self._send_daemon_msg(daemon="controld",
                                    command="reload",
                                    timeout=1)
            status = True
            message = _("Daemon reload queued.")

        elif command == "do_master_failover":
            status = True
            message = _("Master failover request successful.")
            if config.master_failover:
                status = False
                message = _("Ongoing master_failover.")
            if status:
                log_msg = _("Starting master failover...", log=True)[1]
                logger.info(log_msg)
                config.master_failover = True
                config.cluster_status = False
                result = backend.search(object_type="node",
                                        attribute="uuid",
                                        value="*",
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="instance")
                for x_node in result:
                    if not x_node.enabled:
                        continue
                    if x_node.name == config.host_data['name']:
                        continue
                    try:
                        socket_uri = stuff.get_daemon_socket("clusterd", x_node.name)
                    except Exception as e:
                        log_msg = _("Failed to get clusterd socket: {node}: {error}", log=True)[1]
                        log_msg = log_msg.format(node=x_node.name, error=e)
                        logger.critical(log_msg)
                        continue
                    try:
                        clusterd_conn = connections.get("clusterd", socket_uri=socket_uri)
                    except Exception as e:
                        log_msg = _("Cluster connection failed: {node}: {error}", log=True)[1]
                        log_msg = log_msg.format(node=x_node.name, error=e)
                        logger.critical(log_msg)
                        continue
                    try:
                        clusterd_conn.set_master_failover()
                    except Exception as e:
                        log_msg = _("Setting master failover status failed: {node}: {error}", log=True)[1]
                        log_msg = log_msg.format(node=x_node.name, error=e)
                        logger.critical(log_msg)
                    finally:
                        clusterd_conn.close()

            # Do final sync.
            if status:
                from otpme.lib.classes.command_handler import CommandHandler
                # Sync data objects and sessions.
                try:
                    master_node = multiprocessing.master_node['master']
                except KeyError:
                    status = False
                    message = _("No master node elected.")
                if status:
                    try:
                        socket_uri = stuff.get_daemon_socket("clusterd", master_node)
                    except Exception as e:
                        log_msg = _("Failed to get clusterd socket: {node}: {error}", log=True)[1]
                        log_msg = log_msg.format(node=x_node.name, error=e)
                        logger.critical(log_msg)
                        socket_uri = None
                    clusterd_conn = None
                    if socket_uri:
                        try:
                            clusterd_conn = connections.get("clusterd", socket_uri=socket_uri)
                        except Exception as e:
                            log_msg = _("Cluster sync connection failed: {node}: {error}", log=True)[1]
                            log_msg = log_msg.format(node=x_node.name, error=e)
                            logger.critical(log_msg)
                    if clusterd_conn:
                        log_msg = _("Starting sync of data objects...", log=True)[1]
                        logger.info(log_msg)
                        try:
                            clusterd_conn.sync()
                        except Exception as e:
                            log_msg = _("Master failover sync failed: {node}: {error}", log=True)[1]
                            log_msg = log_msg.format(node=x_node.name, error=e)
                            logger.critical(log_msg)
                        finally:
                            clusterd_conn.close()
                    command_handler = CommandHandler()
                    while True:
                        try:
                            socket_uri = stuff.get_daemon_socket("syncd", master_node)
                        except Exception as e:
                            log_msg = _("Failed to get syncd socket: {error}", log=True)[1]
                            log_msg = log_msg.format(error=e)
                            self.logger.warning(log_msg)
                            time.sleep(1)
                            continue
                        try:
                            sync_status = command_handler.do_sync(sync_type="objects",
                                                                skip_object_deletion=True,
                                                                socket_uri=socket_uri,
                                                                realm=config.realm,
                                                                site=config.site,
                                                                max_tries=3)
                        except Exception as e:
                            log_msg = _("Final sync of objects failed: {error}", log=True)[1]
                            log_msg = log_msg.format(error=e)
                            logger.warning(log_msg)
                            sync_status = False
                        if sync_status is not False:
                            status = True
                            break

            if status:
                while True:
                    config.touch_node_sync_file()
                    #new_master_vote = calc_node_vote()
                    #multiprocessing.node_votes[config.host_data['name']] = new_master_vote
                    try:
                        master_node = multiprocessing.master_node['master']
                    except:
                        time.sleep(0.01)
                        continue
                    if master_node != self.host_name:
                        log_msg = _("Waiting for node to get master node...", log=True)[1]
                        logger.info(log_msg)
                        time.sleep(1)
                        continue
                    break

        response = self.build_response(status, message, encrypt=False)
        return response

    def _close(self):
        pass
