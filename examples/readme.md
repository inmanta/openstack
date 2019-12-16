# Examples Index

1. vm.cf: make a virtual machine in an existing tenant, on an existing subnet, with a given image
2. vm_and_floating_ip.cf: same as above, but with floating ip
3. find_image_and_flavor.cf: discover image id and flavor name from the model
4. tenant.cf: setup a new tenant, with default network, subnet and upstream router, requires admin access


## Running examples

These examples require you to have access to an openstack instance.

1. Store your openstack credentials in the following environment variables

| Variable          | Description             |
|-------------------|-------------------------|
| OS_AUTH_URL       | The Openstack Auth URL  |
| OS_USERNAME       | Your Openstack username |
| OS_PASSWORD       | Your Openstack password |
| OS_PROJECT_NAME   | The name of the project to deploy the VM to|


2. Create a project to run the example from, using [cookie cutter](https://github.com/cookiecutter/cookiecutter)

```bash
> pip install --user cookiecutter
> cookiecutter gh:inmanta/inmanta-project-template

project_name [project]: openstacktest
project_description []: 
author [Inmanta]: 
author_email [code@inmanta.com]: 
license [ASL 2.0]: 
copyright [2019 Inmanta]: 
repo_url [https://github.com/inmanta/]: 
Select install_mode:
1 - release
2 - master
3 - prerelease
Choose from 1, 2, 3 (1, 2, 3) [1]: 1

> cd openstacktest
```

3. Copy the content of the example to the project's `main.cf`
4. Fill in the variables on top of the example file
5. Deploy as a normal project