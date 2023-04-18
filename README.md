# iam-extractor

Command Line tool that will extract an existing AWS IAM Role and output a YAML snippet that can be cut and pasted into a CloudFormation or SAM template.

## Build

Using a recent version of golang, build with:

```sh
make
```

Install locally in `$GOPATH/bin`:

```sh
make install
```

## Usage

```sh
iam-extractor --role-name=my-existing-role
```

*Full Options*

``````
usage: iam-extractor --role-name=<role name> --file-name=<output file name>

arguments:

	-r, --role-name			AWS IAM Role Name to extract
	-s, --suppress-output-stdout	Output the yaml fragment to stdout
	--file-name			The name of the file to write the output to. Optional.
