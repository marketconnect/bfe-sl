zip:
	rm function.zip
	zip -r function.zip . -x 'patch.diff' '*/patch.diff' '.git/*' '*/.git/*' 'git/*' '*/git/*'
