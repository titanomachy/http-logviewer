#!/usr/bin/env bash
set -euo pipefail

PLAN_FILE="./PLANS/PLAN.md"
README_SKILL="/home/joa/Code/skills/readme-file/"
NIM_TECH_SKILL="/home/joa/Code/skills/nim-tech-stack/"
TERMINAL_GIF_RECORDER="/home/joa/Code/skills/terminal-gif-recorder/"

while grep -q '\[ \]' "$PLAN_FILE"; do
  echo "--- Starting work on next category via agy ---"
  agy --dangerously-skip-permissions --mode accept-edits --print-timeout 30m -p "Use \"$NIM_TECH_SKILL\" skill for building the program.
    Use \"$README_SKILL\" skill for creating the README.md file.
    Read \"$PLAN_FILE\". Execute only the first incomplete category:
    Work according to the specifications in the specs/ folder. Only deviate if absolutely necessary, and make a note of it.
    1. Mark the active item as [/].
    2. Implement the requested changes.
    3. Add or update tests in the tests/ folder and run verifcationtests.
    4. Markeer het item als [x] zodra de tests slagen.
    5. Add or update documentation in README.md, in code comments and in Nim generated documentation.
    6. Add or update code examples in the examples/ folder for this category and its items.
    7. Add or update finished categories and items to CHANGELOG.md
    8. Add or update images or animated gifs of examples or code examples to README.md with \"$README_SKILL\" and \"$TERMINAL_GIF_RECORDER\"
    9. If all items in this category are at [x]: enter 'git add . && git commit -m \"{enter an appropriate commit message here regarding the completed category and items}\"' and exit.
    Stop immediately upon encountering unresolvable test errors."
done

echo "Completed: No more outstanding items in $PLAN_FILE. Github CI step is left out of this loop on purpose for now."
