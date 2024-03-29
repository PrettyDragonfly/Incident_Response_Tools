import json
from pytaxonomies import Taxonomy
from pytaxonomies import Predicate
from pytaxonomies import Entry

tools = open("../ressources/IR_tools.md", 'r')

lines = tools.readlines()
tools.close()

tools_categories = {}
ok = False
for line in lines:
    if not ok:
        if line.__contains__("## Contents"):
            ok = True
    else:
        if line.__contains__("##"):
            break
        else:
            temp = line
            temp = temp.replace('- [', '')
            temp = temp.replace(']', '')
            temp = temp.replace('\n', '')
            t = temp.split("(")
            tools_categories[t[0]] = {}
del tools_categories['']
del tools_categories['Videos']

# ------------
# SCRAP DATA |
# ------------

for cat in tools_categories:
    ok = False
    for line in lines:
        if not ok:
            if line.__contains__("### "+cat):
                ok = True
        else:
            if line.__contains__("###"):
                break
            else:
                temp = line
                temp = temp.replace('* [', '')
                temp = temp.replace(']', '')
                temp = temp.replace('\n', '')
                temp = temp.split(" - ")
                if len(temp) > 1:
                    t = temp[0].split("(")
                    tools_categories[cat][t[0]] = temp[1]

# ------------------------
# STORE DATA IN TAXONOMY |
# ------------------------

# Declare taxonomy
taxonomy = Taxonomy()

taxonomy.name = "incident-response-tools"
taxonomy.description = "This taxonomy aims to classify incident response tools."
taxonomy.version = 1
taxonomy.expanded = "Incident response tools"

# Declare predicates
predicates = {}

for cat in tools_categories:
    predicates[cat] = Predicate()
    predicates[cat].expanded = cat
    predicates[cat].predicate = cat.strip().replace(" ", "_")

# Declare entries
entries_dict = {}

for cat in tools_categories:
    entries_dict[cat] = []
    for tools in tools_categories[cat]:
        temp = Entry()
        temp.expanded = tools
        name = tools
        name = name.lower()
        name = name.strip()
        name = name.replace(' ', '_')
        temp.value = name
        temp.description = tools_categories[cat][tools]
        entries_dict[cat].append(temp)

# Add entries to predicates
for cat in tools_categories:
    for entry in entries_dict[cat]:
        predicates[cat].entries[entry] = entry

# Add predicates to taxonomy
for cat in tools_categories:
    taxonomy.predicates[cat.strip().replace(' ', '_')] = predicates[cat]

# ---------------------
# EXPORT DATA IN JSON |
# ---------------------

with open("../json/incident-response-tools.json", 'wt', encoding='utf-8') as f:
    json.dump(taxonomy.to_dict(), f, indent=2, ensure_ascii=False)
    print("")
    print("Now you can observe the result with the following command :")
    print("cat ../json/incident-response-tools.json")
