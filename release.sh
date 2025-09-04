export GITHUB_TOKEN=$(gh auth token)
python3 release_helper/do_release.py
