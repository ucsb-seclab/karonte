Configuration file
==
A configuration file is a JSON file containing the following keys:
Each configuration file is structured as follows

|        Key        |                                 Description                                |    Expected Value   | Optional/Mandatory | Linux/Blob |                                        Notes                                       |
|:-----------------:|:--------------------------------------------------------------------------:|:-------------------:|:------------------:|:----------:|:----------------------------------------------------------------------------------:|
|      fw_path      |                            Firmware sample path                            |        String       |      Mandatory     |    Both    |                                          -                                         |
|        bin        |                List of binaries to consider  in the analysis               |   List of  strings  |      Optional      |    Both    |               If present, the border binary discovery step is skipped              |
|   pickle_parsers  |                  Path to the border  binaries pickle file                  |        String       |      Optional      |    Linux   |                                          -                                         |
|       stats       | Log statistics about  analysis (e.g., running time,  path complexity etc.) | String:  True/False |      Mandatory     |    Both    | Alerts for dangerous data flows are always indicated even if stats is set to false |
|     data_keys     |                        List of data keys to consider                       |   List of strings   |      Optional      |    Both    |                                          -                                         |
|     base_addr     |                       Base address of the blob binary                      |        String       |      Mandatory     |    Blob    |                          String should be in  hexadecimal                          |
|   eg_source_addr  |      Function that introduces user input (e.g., read from hard drive)      |        String       |      Mandatory     |    Blob    |                          String should be in  hexadecimal                          |
|      glob_var     |           Address of global variable  known to contain user input          |        String       |      Optional      |    Both    |                                          -                                         |
|        arch       |                                Architecture                                |        String       |      Mandatory     |    Blob    |                                     angr's arch                                    |
|    only_string    |             Consider only the data_keys indicated by data_keys             | String:  True/False |      Optional      |    Both    |                                          -                                         |
| angr_explode_bins |                  List of binaries that angr cannot handle                  |   List of  strings  |      Optional      |    Linux   |                   Each string is the name of the binary to ignore                  |