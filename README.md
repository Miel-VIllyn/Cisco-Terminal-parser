# Cisco-Terminal-parser
Parses the output from commands input in cisco terminal into markdown files.

# Workings
Type all the show commands you need in the cisco terminal and then just copy the output into a file.

Drag that file to the `./data/` folder and let the program work. The output will be put in the `./parsed/` folder.

The program is able to live update the configuration. The program can keep running while you input changes in the files.
If items are removed form the terminal files, these changes will also reflect in the markdown file.