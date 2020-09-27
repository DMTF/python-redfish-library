#!/bin/bash

# Collect change log info
CHANGES="## [$1] - $(date +'%Y-%m-%d')"$'\n'
echo "Enter changes:"
while : ; do
    read CHANGE
    if [ "$CHANGE" = "" ]; then
        break
    fi

    CHANGES="$CHANGES- $CHANGE"$'\n'
done

# Rebase
git checkout master
git fetch && git rebase origin

# Update the version number in setup.py and src/redfish/__init__.py
sed -i -E 's/      version=.+,/      version='\'$1\'',/' setup.py
sed -i -E 's/__version__ = .+/__version__ = "'$1'"/' src/redfish/__init__.py

# Update the change log file
ex CHANGELOG.md <<eof
3 insert
$CHANGES
.
xit
eof

# Commit and push changes
git add CHANGELOG.md setup.py src/redfish/__init__.py
git commit -m "$1 versioning"
git push origin master

# Release to pypi
python3 setup.py sdist && twine upload dist/*

# Make new release in GitHub
CHANGES="Changes since last release:"$'\n\n'"$CHANGES"
gh release create $1 -n "$CHANGES"
