=TEMPL=host
 {
  "name": "h{{.}}",
  "uid": "id-h{{.}}",
  "ipv4-address": "10.1.1.{{.}}"
 }
=END=

############################################################
=TITLE=Change group members
=DEVICE=
{
 "Groups": [
  {
   "name": "g1",
   "uid": "id-1",
   "members": ["h1", "h2", "h3"]
  }
 ],
 "Hosts": [
  [[host 1]],
  [[host 2]],
  [[host 3]]
 ]
}
=NETSPOC=
{
 "Groups": [
  {
   "name": "g1",
   "members": ["h4", "h3", "h2", "h5"]
  }
 ],
 "Hosts": [
  [[host 2]],
  [[host 3]],
  [[host 4]],
  [[host 5]]
 ]
}
=OUTPUT=
add-host
{"name":"h4","ignore-warnings":true,"ipv4-address":"10.1.1.4"}
add-host
{"name":"h5","ignore-warnings":true,"ipv4-address":"10.1.1.5"}
set-group
{"members":{"add":["h4","h5"]},"uid":"id-1"}
set-group
{"members":{"remove":["h1"]},"uid":"id-1"}
delete-host
{"uid":"id-h1"}
=END=

############################################################
=TITLE=Replace group by hosts, delete group
=DEVICE=
{
 "Groups": [
  {
   "name": "g1",
   "uid": "id-1",
   "members": ["g2", "h3"]
  },
  {
   "name": "g2",
   "uid": "id-2",
   "members": ["h1", "h2", "h4"]
  }
 ],
 "Hosts": [
  [[host 1]],
  [[host 2]],
  [[host 3]],
  [[host 4]]
 ]
}
=NETSPOC=
{
 "Groups": [
  {
   "name": "g1",
   "members": ["h1", "h2", "h3"]
  }
 ],
 "Hosts": [
  [[host 1]],
  [[host 2]],
  [[host 3]]
 ]
}
=OUTPUT=
set-group
{"members":{"add":["h1","h2"]},"uid":"id-1"}
set-group
{"members":{"remove":["g2"]},"uid":"id-1"}
delete-group
{"uid":"id-2"}
delete-host
{"uid":"id-h4"}
=END=

############################################################
=TITLE=Replace hosts by group, add group
=DEVICE=
{
 "Groups": [
  {
   "name": "g1",
   "uid": "id-g1",
   "members": ["h1", "h2", "h3"]
  }
 ],
 "Hosts": [
  [[host 1]],
  [[host 2]],
  [[host 3]]
 ]
}
=NETSPOC=
{
 "Groups": [
  {
   "name": "g1",
   "members": ["g2", "h3"]
  },
  {
   "name": "g2",
   "members": ["h1", "h2"]
  }
 ],
 "Hosts": [
  [[host 1]],
  [[host 2]],
  [[host 3]]
 ]
}
=OUTPUT=
set-group
{"members":{"add":["g2"]},"uid":"id-g1"}
set-group
{"members":{"remove":["h1","h2"]},"uid":"id-g1"}
add-group
{"name":"g2","members":["h1","h2"]}
=END=
