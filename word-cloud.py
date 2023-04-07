import textwrap
import numpy as np
from dash import Dash
import plotly.graph_objs as go
import random
import pandas as pd
from dash import dcc, html
from dash.dependencies import Input, Output




app = Dash(__name__)

df = pd.read_csv('Comprehensive CAPEC Dictionary.csv')
CAPECids = df['ID']


color = { 'Very High':  'red',
          'High': 'maroon',
          'Medium': 'indigo',
          'Low': 'turquoise',
          'Very Low': 'blue',
          'None': 'lightblue',
          np.nan: 'lightblue'}

weights = {'High': 35,
           'Medium': 27,
           'Low': 18,
           np.nan : 18}

severity_color = [color[val] for val in df['Typical Severity']]
weight_size = [weights[val] for val in df['Likelihood Of Attack']]


@app.callback(
    Output('point-info', 'children'),
    Input('word-cloud', 'clickData')
)

def on_click(clickData):
    """
        This function is a callback function that is triggered when a user clicks on a data point. When a data point is clicked the following data from
         the filtered_df is displayed: Name, Description, link to capec.mitre.org page

        ARGS:
            clickData : a dictionary that contains information about a CAPEC ID on the chart that was selected.
                        ['points'] being a list of all the clicked points
                        [0] being the first point since only one point can be clicked at a time
                        ['pointIndex'] being the index of the first point selected corresponding to the index of the selected CAPEC ID in filtered_df
        RETURNS:
            A HTML Div that contains the name and description of the selected CAPEC ID along with the link to it from the capec.org website
        """

    if clickData is None:
        return html.P('Click on a CAPEC ID to see a description of the attack pattern', style={'color': 'grey', 'fontSize': 15}),
    point_index = clickData['points'][0]['pointIndex']
    name = df.loc[point_index, 'Name']
    description = df.loc[point_index, 'Description']
    id = CAPECids[point_index]
    wraptext = '\n'.join(textwrap.wrap(description, width=100))
    text = f'To learn more follow this link: '
    link = f'https://capec.mitre.org/data/definitions/{id}'

    return html.Div([
        html.H3(children=name, style={'color': 'darkgrey', 'fontSize': 25}),
        html.P(children=wraptext, style={'color': 'grey', 'fontSize': 15}),
        html.P(children=[text, html.A(link, href=link, target='_blank')], style={'color': 'grey', 'fontSize': 12}),
    ])


@app.callback(
    Output('table', 'children'),
    Input('radio-items', 'value'),
    Input('word-cloud', 'clickData')
)
def update_table(value, clickData):
    """
        This function is a callback function that is triggered when a user clicks on a data point. The selected data point is the same point as
        the function on_click seen above. This function contains radio button items such as related weaknesses, instances, and mitigations.
        Each of its respective information from the comprehensive CAPEC csv file is displayed when corresponding radio item is selected.

        ARGS:
            clickData : a dictionary that contains information about a CAPEC ID on the chart that was selected.
                        ['points'] being a list of all the clicked points
                        [0] being the first point since only one point can be clicked at a time
                        ['pointIndex'] being the index of the first point selected corresponding to the index of the selected CAPEC ID in filtered_df
        RETURNS:
            A HTML Div containing data from comprehensive CAPEC csv file depending on which radio item was selected
        """

    if clickData is None:
        return html.P('If a CAPEC ID is clicked, information will be displayed here.', style={'color': 'grey', 'fontSize': 15})

    point_index = clickData['points'][0]['pointIndex']

    if value == 'weakness':
        weakness = df.loc[point_index, 'Related Weaknesses']
        if pd.isna(weakness):
            return html.P('No weakness data available', style={'color': 'red', 'fontSize': 15})
        cwe_ids = weakness.split("::")[1:-1]
        list_of_cwe=[]
        text = 'Below you will find a link of realted weaknesses from the Common Weakness Enumeration (CWE) catolog'
        for cwe in cwe_ids:
            link = f'https://cwe.mitre.org/data/definitions/{cwe}'
            list_of_cwe.append(html.P(html.A(link, href=link, target='_blank'), style={'color':'grey','fontSize':15}))

        return html.Div([
            html.P(text,style = {'color': 'grey', 'fontSize': 15}),
            html.P(list_of_cwe)
            ])

    elif value == 'instance':
        instance = df.loc[point_index, 'Example Instances']
        if pd.isna(instance):
            return html.P('No example instance data available', style={'color': 'red', 'fontSize': 15})
        text = instance.replace('::', '\n')
        return html.P(text, style={'color': 'grey', 'fontSize': 15})

    elif value == 'mitigation':
        mitigation = df.loc[point_index, 'Mitigations']
        if pd.isna(mitigation):
            return 'No mitigation available'
        text = mitigation.replace('::', '\n')
        return html.P(text,style={'color': 'grey', 'fontSize': 15})


@app.callback(
    Output('word-cloud', 'figure'),
    Input('dropdown', 'value')
)
def update_figure(cids):
    """
    This function is a callback function that is triggered when a user selects a value from the dropdown menu. The value that is selected
    via dropdown menu is equivalent to the number of CAPEC IDs that are going to be displayed on the word cloud. This funciton updates the
    word cloud to show the correct amount of CAPEC IDs.

    ARGS:
        cids: a integer (default value = 20) chosen by the user via dropdown menu. Can be a value 20-50.

    RETURNS:
        fig: the updated word cloud with the correct number of CAPEC IDs
    """

    layout = go.Layout( {'xaxis': {'showgrid': False, 'showticklabels': False, 'zeroline': False},
                    'yaxis': {'showgrid': False, 'showticklabels': False, 'zeroline': False}},
                    width =760,
                    height =760
)
#cids is going to dictate how many CAPEC ids are shown
#range(num) represents range of values to be randomly selected from, reducing the chances of overlapping points.

    fig = go.Figure(data=go.Scatter(x=random.sample(range(500), cids),
                 y= random.sample(range(500), cids) ,
                 mode='text',
                 text=CAPECids,
                  hovertext=df['Name'],
                  hoverinfo='text',
                 textfont={'size': weight_size,
                           'color': severity_color}),
                layout=layout)

    return fig


fig = update_figure(20)
#app.layout describes what the app looks like and is a hierarchical tree of components
app.layout = html.Div(children=[
    html.H1('CAPEC Word Cloud'),
    html.P("""
    Common Attack Pattern Enumeration and Classification (CAPEC) is a public catalog of common attack patterns that helps users understand
     how adversaries exploit weaknesses in applications. This dash application displays a word cloud visualization of the CAPEC catolog, 
     and aims to provide a structured way to describe attack patterns and help security professionals better understand how attackers operate, 
     which in turn helps them better defend against attacks. Each attack pattern in the CAPEC catalog has a unique identifier and is described in detail, 
     including information on the attack's goals, typical defenses, and related attack patterns, etc. This application includes radio items, hover and click 
     components as a way to promote interactive learning. 
    """),
    html.Br(),
    html.P("Select the number of CAPEC IDs"),
    dcc.Dropdown(
        id='dropdown',
        options= [
        {'label': '20', 'value': 20},
        {'label': '30', 'value': 30},
        {'label': '40', 'value': 40},
        {'label': '50', 'value': 50}
        ], value=20
    ),
    html.Div(id='num-of-ids'),
 html.Div([
        dcc.Graph(
            id='word-cloud',
            figure=fig,
            clickData= None,
            style = {'width': '50%', 'display': 'inline-block'}
        ),
        html.Div([
            html.P('Word Cloud Legend', style={'color':'black','fontSize':16}),
            html.Div([
                html.P(children='Severity:', style={'color': 'black', 'margin': '0px 10px' }),
                html.P('Very High', style={'color': color['Very High'], 'margin': '0px 10px' }),
                html.P('High', style={'color': color['High'], 'margin': '0px 10px'}),
                html.P('Medium', style={'color': color['Medium'], 'margin': '0px 10px'}),
                html.P('Low', style={'color': color['Low'], 'margin': '0px 10px'}),
                html.P('Very Low', style={'color': color['Very Low'], 'margin': '0px 10px'}),
                html.Br(),

            ], style={'display': 'flex', 'fontSize': 16}),
            html.Br(),
            html.Div([
                html.P(children='Likelihood of Attack:',style={'color': 'black', 'margin': '0px 10px' }),
                html.P('High', style={'color':'black','fontSize': weights['High'], 'margin': '0px 15px' }),
                html.P('Medium', style={'color':'black','fontSize': weights['Medium'], 'margin': '0px 15px'}),
                html.P('Low', style={'color':'black','fontSize': weights['Low'], 'margin': '0px 15px'}),
            ], style={'display': 'flex', 'fontSize': 16}),
            html.Div(id='point-info')
    ], style={'fontSize': 18,'width': '50%', 'marginLeft': 40, 'marginTop': 80}
        )], style={'display': 'flex'}),
    html.Br(),
    html.Div([
        html.P('Cick on one of the following to learn about the related weaknesses, example instances and mitigations of the corresponding attack pattern'),
        dcc.RadioItems(
            id = 'radio-items',
            options = [
        {'label': 'Related Weaknesses', 'value': 'weakness'},
        {'label': 'Instances', 'value': 'instance'},
        {'label': 'Mitigation', 'value': 'mitigation'},
        ],
            value='mitigation'),
        html.Div(id='table')
    ])
    ])
if __name__== '__main__':
    app.run_server(debug=True)

