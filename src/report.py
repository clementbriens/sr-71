import pandas as pd
from jinja2 import Environment, FileSystemLoader
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib import rcParams
from matplotlib import colors
from matplotlib import cm
import numpy as np





def generate_report(target):
    rcParams.update({'figure.autolayout': True})
    # loading template
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template("templates/template.html")


    # reading data
    domains_df = pd.read_csv('reports/{}/data/{}_domains.csv'.format(target,target), index_col = 0)
    domains_df = domains_df.fillna('')
    domains_df.style.set_table_attributes('class="table-hover"')
    domains_df['domain'] = domains_df['domain'].apply(lambda x: '<a href="{}">{}</a>'.format(x,x))

    vulns_df = pd.read_csv('reports/{}/data/{}_vulns.csv'.format(target, target), index_col = 0)
    vulns_df = vulns_df.fillna('')
    vulns_df = vulns_df.sort_values(by = ['severity'], ascending=False)



    cwe_df = pd.read_csv('reports/{}/data/{}_cwes.csv'.format(target,target), index_col = 0)
    cwe_df = cwe_df.fillna('')

    tech_df = pd.read_csv('reports/{}/data/{}_technologies.csv'.format(target,target), index_col = 0)
    tech_df = tech_df.fillna('').drop_duplicates().sort_values(by = ['type'])
    techs = []
    nb_techs = []
    for t in domains_df['technologies']:
        techs = t.split(',')
        for tech in techs:
            if tech not in techs:
                techs.append(tech)
            if tech not in nb_techs:
                nb_techs.append(tech)


    # generate plots

    vuln_chart = vulns_df.groupby('domain')['vulnerability'].nunique()
    chart = vuln_chart.plot.barh(title = 'Vulnerabilies found per domain')
    chart.set_xlabel('Vulnerabilities found')
    chart.set_ylabel('')

    vuln_chart_path = 'reports/{}/plots/vulnerability_domains.png'.format(target, target)
    plt.savefig(vuln_chart_path)

    bins = pd.cut(vulns_df['severity'], list(range(0,11)))


    severity_df = vulns_df.groupby(bins)['severity'].agg(['count'])
    sev_chart = severity_df.plot.bar(title = 'Vulnerabilities by severity')
    # sev_chart = sns.barplot(x = severity_df.index, y = severity_df.values, orient = "h")
    sev_chart.set_ylabel('Vulnerabilities found')
    sev_chart.set_xlabel('Common Vulnerability Severity Score (CVSS)')
    labels = []
    for l in range(0,11):
        labels.append('{}-{}'.format(l, l+1))
    sev_chart.set_xticklabels(labels, rotation=0)
    # chart = sns.barplot( x = vulns_df.domain.unique(), y = vuln_chart.values, orient = "h")
    sev_chart_path = 'reports/{}/plots/{}_vulnerability_severity.png'.format(target, target)
    plt.savefig(sev_chart_path)


    #generating live links

    vulns_df['domain'] = vulns_df['domain'].apply(lambda x: '<a href="{}">{}</a>'.format(x,x))
    vulns_df['vulnerability'] = vulns_df['vulnerability'].apply(lambda x: '<a href="https://www.cvedetails.com/cve/{}">{}</a>'.format(x,x))

    cwe_df['cve'] = cwe_df['cve'].apply(lambda x: '<a href="https://www.cvedetails.com/cve/{}">{}</a>'.format(x,x))
    cwe_df['cwe_id'] = cwe_df['cwe_id'].apply(lambda x: '<a href="https://cwe.mitre.org/data/definitions/{}.html">{}</a>'.format(x.split('-')[1],x))
    cwe_df['domain'] = cwe_df['domain'].apply(lambda x: '<a href="{}">{}</a>'.format(x,x))

    template_vars = {
    "target" : target,
    "nb_domains" : len(domains_df),
    "nb_tech" : len(nb_techs),
    "domains_df": domains_df.to_html(index=False, classes='table-hover', render_links=True, escape=False),
    "unique_cves" : len(vulns_df['vulnerability'].unique()),
    "unique_domains" : len(vulns_df['domain'].unique()),
    "mean_severity" : round(vulns_df['severity'].mean(),1),
    "nb_critical" : len(vulns_df.loc[vulns_df['severity'] >= 8]),
    "most_common_vulnerability": vulns_df.vulnerability_types.mode().values[0],
    "vulns_df" : vulns_df.to_html(index=False, classes='table-hover', render_links=True, escape=False),
    "vuln_chart_path" : vuln_chart_path,
    "sev_chart_path" : sev_chart_path,
    "cwe_df" : cwe_df.to_html(index=False, render_links=True, escape=False),
    "unique_cwes" : len(cwe_df['cwe_id'].unique()),
    "most_common_weakness" : cwe_df.cwe_name.mode().values[0],
    'unique_tech' : len(tech_df['technology'].unique()),
    'most_common_type' : tech_df.type.mode().values[0],
    'most_common_tech': tech_df.technology.mode().values[0],
    'tech_df' : tech_df.to_html(index=False, render_links=True, escape=False)
    }

    html_out = template.render(template_vars)

    Html_file= open("reports/{}/{}.html".format(target, target),"w")
    Html_file.write(html_out)
    Html_file.close()




if __name__ == '__main__':
    target = 'orpheus-cyber.com'
    generate_report(target)
