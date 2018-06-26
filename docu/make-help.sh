#!/bin/bash

football_dir="${football_dir:-../football}"

function make_latex_include
{
    local cmd="$1"

    echo '\begin{verbatim}'
    eval "$cmd" | sed 's/\\/\\\\/g'
    echo '\end{verbatim}'
}

make_latex_include "../userspace/marsadm --help" > marsadm.help
make_latex_include "(cd $football_dir/ && ./football.sh --help)" > football.help
make_latex_include "(cd $football_dir/ && ./football.sh --help --verbose)" > football-verbose.help
make_latex_include "(cd $football_dir/ && ./screener.sh --help)" > screener.help
make_latex_include "(cd $football_dir/ && ./screener.sh --help --verbose)" > screener-verbose.help
