def configurations = [
  [ platform: "docker", jdk: "11" ],
  [ platform: "windows", jdk: "11" ]
]
buildPlugin(tests: [skip: true], spotbugs: [qualityGates: [[threshold: 1000, type: 'TOTAL', unstable: false]] ])
