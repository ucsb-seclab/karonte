import os
import sys
import json
import networkx
import webbrowser

from threading import Timer
from collections import namedtuple, defaultdict

import dash
import dash_core_components as dcc
import dash_html_components as html
import plotly.express as px
import plotly.graph_objects as go
from textwrap import dedent as d
import pandas as pd

from utils import decompile_function, get_edge_index, get_alert_str


KaronteRes = namedtuple('KaronteRes', ['bdg', 'bdg_info', 'interactions', 'bbinaries', 'alerts', 'n_bins'])
res = None

pos_to_obj = {}
mapping = {}
rev_mapping = {}
bdg_graph = None
selected_alert = None

PORT = 8050

external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']
app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

colors = {
    'background': '#1D2126',
    'text': '#FFFFFF'
}


def parse_json_log(content):
    data = json.loads(content)
    bbinaries = data['border_binaries']['binaries']
    bdg_info = data['bdg']
    bdg = {}
    interactions = defaultdict(list)
    for node, succ_nodes in bdg_info.items():
        if node in ['orphans', 'basic_blocks', 'analysis_time']:
            # TODO: @nilo fix this 
            continue

        bdg[node] = [x['dst_bin'] for x in bdg_info[node]]

        for succ_node in succ_nodes:
            interactions[(os.path.basename(node), os.path.basename(succ_node['dst_bin']))].append(succ_node)

    alerts = data['alerts']['alerts']
    for alert in alerts:
        alert['bins_path'] = [os.path.basename(b) for b in alert['bins_path']]

    n_bins = data['num_binaries']

    return KaronteRes(bdg, bdg_info, interactions, bbinaries, alerts, n_bins)


def bdg_graph_fig(alert=None):
    global pos_to_obj, mapping, rev_mapping, bdg_graph

    bdg_graph = networkx.DiGraph(res.bdg)

    for node in list(bdg_graph.nodes):
        mapping[node] = os.path.basename(node)
        rev_mapping[os.path.basename(node)] = node


    bbinaries_names = [os.path.basename(b) for b in res.bbinaries]
    bdg_graph = networkx.relabel_nodes(bdg_graph, mapping)
    node_positions = networkx.spring_layout(bdg_graph, seed=31337)

    for node, pos in node_positions.items():
        pos_to_obj[(pos[0], pos[1])] = node

    full_trace = []

    index = 0
    for edge in bdg_graph.edges:
        x0, y0 = node_positions[edge[0]]
        x1, y1 = node_positions[edge[1]]
        red_color = False

        if alert and edge[0] in alert['bins_path']:
            e0_index = alert['bins_path'].index(edge[0])
            red_color = edge[1] == alert['bins_path'][e0_index + 1]

        e_trace = go.Scatter(
                    x=tuple([x0, x1, None]),
                    y=tuple([y0, y1, None]),
                    mode='lines',
                    line=dict(width=2, color= 'Red' if red_color else '#888'),
                    line_shape='spline',
                    opacity=1
                  )

        full_trace.append(e_trace)
        index += 1

    for i, adjacencies in enumerate(bdg_graph.adjacency()):
        node_text = '{}'.format(adjacencies[0])
        node_color = '#1b4482'
        n_line_color = '#444444'

        if adjacencies[0] in bbinaries_names:
            node_text += ' <br>Border Binary'
            node_color = '#eaf9ea'
        if len(adjacencies[1]) > 0:
            node_text += ' <br>No. of connections: {}'.format(len(adjacencies[1]))

        if alert and adjacencies[0] in alert['bins_path']:
            n_line_color = 'Red'

        n_trace = go.Scatter(
            x=(node_positions[adjacencies[0]][0],), y=(node_positions[adjacencies[0]][1],),
            mode='markers',
            hoverinfo='text',
            hovertext=node_text,
            text=adjacencies[0],
            name=adjacencies[0],
            marker=dict(
                 showscale=False,
                 color=[node_color],
                 size=30,
                 line_width=2,
                 line_color = n_line_color
            ),
        )

        full_trace.append(n_trace)

    middle_hover_trace = go.Scatter(
        x=[], y=[], hovertext=[], mode='markers', hoverinfo="text",
        marker={'size': 20, 'color': 'LightSkyBlue'},
        opacity=0
    )

    for edge in bdg_graph.edges:
        if edge[0] == edge[1]:
            # TODO: for now, skip same-node edge labels
            continue

        x0, y0 = node_positions[edge[0]]
        x1, y1 = node_positions[edge[1]]

        data_keys = set([i['data_key'] for i in res.interactions[edge]])

        if alert is not None:
            e_index = get_edge_index(edge, alert['bins_path'])
            if e_index != -1:
                data_keys = [alert['bin_interactions'][e_index]['data_key']]

        hovertext = 'Data keys:<br>' + '<br>'.join(data_keys) 
        x = tuple([(x0 + x1) / 2])
        y = tuple([(y0 + y1) / 2])
        middle_hover_trace['x'] += x
        middle_hover_trace['y'] += y
        middle_hover_trace['hovertext'] += tuple([hovertext])
        pos_to_obj[(x[0], y[0])] = '({}, {})'.format(edge[0], edge[1])

    full_trace.append(middle_hover_trace)

    figure = go.Figure(data=full_trace,
                       layout=go.Layout(
                          showlegend=False,
                          hovermode='closest',
                          margin=dict(b=0,l=0,r=0,t=0),
                          xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, fixedrange=True),
                          yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, fixedrange=True),
                          height=580,
                          clickmode='event+select'
                       ),
            )

    return figure


def set_layout():
    # styles: for right side hover/click component
    styles = {
        'pre': {
            'border': 'thin lightgrey solid',
            'overflowX': 'scroll',
            'color': colors['text'],
            'font-size': '16px'
        }
    }

    app.layout = html.Div(children=[
        html.H1(
            children='Karonte - Identifying multi-binary vulnerabilities in embedded firmware',
            style={
                'textAlign': 'center',
                'color': colors['text']
            }
        ),

        html.H4(children=sys.argv[1], style={
            'textAlign': 'center',
            'color': colors['text']
        }),

       html.H4(children='Total number of binaries: {}'.format(res.n_bins), style={
            'textAlign': 'center',
            'color': colors['text']
        }),

        html.Br(),

        html.Div(
            className="row",
            children=[html.Div(
                className="bdg-container",
                children=[
                    html.Div(
                        className="two columns",
                        children='Selected Alert:',
                        style={
                            'color': colors['text'],
                            'textAlign': 'right',
                            'font-size': '20px'
                        }
                    ),
                    html.Div(
                        className="ten columns",
                        children=[
                            dcc.Dropdown(
                                id='alert-selector',
                                options=[
                                    {'label': 'Alert #{} - {}'.format(i, get_alert_str(j)), 'value': i} for i, j in enumerate(res.alerts)
                                ],
                                value=None
                            ),
                            html.Br(),
                            html.Div(id='output-container-range-slider')
                        ],
                    )
                ]
            )]
        ),

        html.Div(
            className="row",
            children=[
                html.Div(
                    id='bdg-container-id',
                    className="bdg-container",
                    style={'textAlign': 'center'},
                    children=[dcc.Graph(id="bdg", figure=bdg_graph_fig(), config={'displayModeBar': False})],
                ),
            ]
        ),

        html.Div(
            className="row",
            children=[
                html.Div(
                    className="bdg-container",
                    id='box-id',
                    children=[
                        html.Div(
                            children=[
                                html.Pre(id='click-data', style=styles['pre'])
                            ],
                            style={'height': '400px'})
                    ]
                )
            ]
        )
    ])


################################callbacks

@app.callback(
    dash.dependencies.Output('bdg', 'figure'),
    [dash.dependencies.Input('alert-selector', 'value')])
def update_bdg(value):
    global selected_alert
    if value is not None and value != -1:
        alert = res.alerts[value]
        selected_alert = alert
        return bdg_graph_fig(alert=alert)
    else:
        selected_alert = None
        return bdg_graph_fig()


@app.callback(
    dash.dependencies.Output('click-data', 'children'),
    [dash.dependencies.Input('bdg', 'clickData')])
def display_click_data(clickData):
    if clickData is None:
        return ''

    x = clickData['points'][0]['x']
    y = clickData['points'][0]['y']
    obj = pos_to_obj[(x, y)]

    out = obj
    out += '\n------------'

    if obj.startswith('('):
        # this is an edge
        edge = tuple(obj[1:-1].split(', '))

        try:
            e_index = get_edge_index(edge, selected_alert['bins_path'])
        except:
            e_index = 0

        if selected_alert is not None and e_index != -1:
            a_interaction = selected_alert['bin_interactions'][e_index]
            out += '\nData key: {}\n'.format(a_interaction['data_key'])
            out += 'CPF: {}\n'.format(a_interaction['cps'])
            out += 'Buffer address: {}\n'.format(hex(a_interaction['buff_addr']))
            out += 'Sink address: {}\n'.format(hex(a_interaction['sink_address']))
            out += '\n'

        else:
            e_inters = res.interactions[edge]
            # remove duplicates
            e_inters_u = [i for n, i in enumerate(e_inters) if i not in e_inters[n + 1:]]
            for interaction in e_inters_u:
                out += '\nData key: {}\n'.format(interaction['data_key'])
                out += 'CPF sender: {}\n'.format(interaction['cpf_send'])
                out += 'CPF receiver: {}\n'.format(interaction['cpf_recv'])
                out += '\n'

    if selected_alert is not None and obj == selected_alert['bins_path'][-1]:
        out += '\n=== Vulnerable Function ===\n'
        out += decompile_function(rev_mapping[obj], selected_alert)
        out += '\n'

    else:
        if obj in rev_mapping:
            out += '\nFull path: {}'.format(rev_mapping[obj])

        out += '\n'

        if obj in bdg_graph.nodes:
            for succ in bdg_graph.successors(obj):
                out += '\n --> {}'.format(succ)

    return out


def open_browser():
    webbrowser.open_new('http://127.0.0.1:{}/'.format(PORT))


def main():
    if len(sys.argv) != 2:
        print('Use: python viz-results.py <PATH_TO_LOG_FILE>')
        exit()

    try:
        raw_data = open(sys.argv[1]).read()
    except:
        print('Error reading file')
        exit()

    global res
    res = parse_json_log(raw_data)

    set_layout()

    # Timer(1, open_browser).start();
    app.run_server(debug=False, port=PORT)


if __name__ == '__main__':
    main()

