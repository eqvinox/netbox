#!/usr/bin/python3

import psycopg2, json

from netbox.configuration import DATABASE
from dcim.constants import IFACE_MODE_CHOICES, IFACE_FF_CHOICES

ifmode = dict([tuple(i) for i in IFACE_MODE_CHOICES])
ifform = {}
for group in IFACE_FF_CHOICES:
    ifform.update(dict([tuple(i) for i in group[1]]))

from django.views import View
from django.http import HttpResponse, HttpResponseForbidden
from netbox.api import TokenAuthentication

class BulkIfaceView(View):
    http_method_names = ['get', 'head']

    def get(self, request):
        if not (request.user and request.user.is_authenticated):
            if 'HTTP_AUTHORIZATION' not in request.environ:
                return HttpResponseForbidden()
            auth = request.environ['HTTP_AUTHORIZATION']
            if not auth.lower().startswith('token '):
                return HttpResponseForbidden()
            token = auth[6:]
            user, token = TokenAuthentication().authenticate_credentials(token)
            if not user.is_authenticated:
                return HttpResponseForbidden()

        with psycopg2.connect('dbname=%s user=%s password=%s host=%s' % (DATABASE['NAME'], DATABASE['USER'], DATABASE['PASSWORD'], DATABASE['HOST'])) as db:
            with db.cursor() as cursor:
                query = '''
select
    di.id, di.name, di.description, enabled, form_factor, mtu, mgmt_only, mac_address, mode,
    json_build_object('id', dd.id, 'name', dd.name, 'display_name', dd.name,
            'url', 'https://netbox.c3noc.net/api/dcim/devices/' || dd.id::text || '/')
            as device,
    coalesce(dca.id, dcb.id) as conn_id,
    coalesce(dca.interface_a_id, dcb.interface_a_id) as interface_a_id,
    coalesce(dca.interface_b_id, dcb.interface_b_id) as interface_b_id,
    coalesce(dca.connection_status, dcb.connection_status) as connection_status,
    di.lag_id,
    (select json_build_object('id', cit.id, 'port_speed', port_speed, 'upstream_speed', upstream_speed, 'pp_info', pp_info, 'xconnect_id', xconnect_id, 'term_side', term_side,
                'circuit', json_build_object('id', cit.circuit_id, 'cid', cic.cid, 'url', 'https://netbox.c3noc.net/api/circuits/circuits/' || cic.id::text || '/' ))
            from circuits_circuittermination cit
                join circuits_circuit cic on cit.circuit_id = cic.id
            where cit.interface_id = di.id)
        as circuit_termination,
    case
        when u_vl.id is null then null
        else json_build_object('id', u_vl.id, 'vid', u_vl.vid, 'name', u_vl.name,
                'display_name', u_vl.vid::text || ' (' || u_vl.name || ')',
                'url', 'https://netbox.c3noc.net/api/ipam/vlans/' || u_vl.id::text || '/')
        end as untagged_vlan,
    (select json_agg(json_build_object('id', t_vl.id, 'vid', t_vl.vid, 'name', t_vl.name,
                'display_name', t_vl.vid::text || ' (' || t_vl.name || ')',
                'url', 'https://netbox.c3noc.net/api/ipam/vlans/' || t_vl.id::text || '/'))
            from dcim_interface_tagged_vlans t_vl_t join ipam_vlan t_vl on t_vl.id = t_vl_t.vlan_id where t_vl_t.interface_id = di.id)
        as tagged_vlans,
    (select array_agg(name)
            from taggit_taggeditem left join taggit_tag on tag_id = taggit_tag.id where object_id = di.id and content_type_id = 19)
        as tags
    from dcim_interface di
        left join dcim_device dd on di.device_id = dd.id
        left join dcim_interfaceconnection dca on dca.interface_a_id = di.id
        left join dcim_interfaceconnection dcb on dcb.interface_b_id = di.id
        left join ipam_vlan u_vl on u_vl.id = di.untagged_vlan_id
    order by di.id
'''

                cursor.execute(query)
                cols = [col.name for col in cursor.description]
                rows = cursor.fetchall()

        out = []
        by_id = {}
        for row in rows:
            rowdata = dict(zip(cols, row))
            if rowdata['tagged_vlans'] is None:
                rowdata['tagged_vlans'] = []
            rowdata['tagged_vlans'] = sorted(rowdata['tagged_vlans'], key = lambda x: x['id'])
            if rowdata['tags'] is None:
                rowdata['tags'] = []
            rowdata['tags'] = sorted(rowdata['tags'])
            if rowdata['mode'] is not None:
                rowdata['mode'] = { 'value': rowdata['mode'], 'label': ifmode.get(rowdata['mode']) }
            if rowdata['form_factor'] is not None:
                rowdata['form_factor'] = { 'value': rowdata['form_factor'], 'label': ifform.get(rowdata['form_factor']) }
            by_id[rowdata['id']] = rowdata
            out.append(rowdata)
        for row in out:
            a, b = row['interface_a_id'], row['interface_b_id']
            if row['conn_id'] is None:
                row['interface_connection'] = None
            else:
                other = a if row['id'] == b else b
                row['interface_connection'] = {
                    'id': row['conn_id'],
                    'connection_status':
                        { 'label': 'Connected', 'value': True }
                            if row['connection_status'] else
                                { 'label': '???', 'value': False },
                    'interface': {
                        'device': by_id[other]['device'],
                        'id': other,
                        'name': by_id[other]['name'],
                        'url': 'https://netbox.c3noc.net/api/dcim/interfaces/%d/' % other,
                    }
                }
            lag_id = row['lag_id']
            if lag_id is not None:
                row['lag'] = {
                    'id': lag_id,
                    'name': by_id[lag_id]['name'],
                    'device': by_id[lag_id]['device'],
                    'url': 'https://netbox.c3noc.net/api/dcim/interfaces/%d/' % lag_id,
                }
            else:
                row['lag'] = None
            del row['interface_a_id']
            del row['interface_b_id']
            del row['connection_status']
            del row['conn_id']
            del row['lag_id']

            row['is_connected'] = row['interface_connection'] is not None or row['circuit_termination'] is not None

        out = {
            'count': len(out),
            'previous': None,
            'next': None,
            'results': out,
        }
        data = json.dumps(out).encode('UTF-8')

        response = HttpResponse()
        response['Content-Type'] = 'application/json'
        response['Content-Length'] = '%s' % len(data)
        response.write(data)

        return response

from django.conf.urls import url

urlpatterns = [
    url(r'^interfaces/$', BulkIfaceView.as_view(), name='bulk_interfaces'),
]
