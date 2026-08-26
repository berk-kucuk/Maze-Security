Nmap data files (nmap-services, nmap-service-probes, nmap-os-db, scripts/) are
placed here by native-tools/build.sh when the nmap binary is built. They are
copied to filesDir at runtime and passed to nmap via --datadir.
