# UPG External tests

The tests don't need Docker to run, but dockerized environment is
provided to make it easier to run them.

In order to run the tests, first build the image. Instead of
`upg:release`, you need to specify the base U-Node image you want to
use.

```console
$ docker build -t exttest-dev -f Dockerfile.dev --build-arg BASE=upg:release .
```

Then start the environment. `-v $PWD:/exttest` is optional and is only
needed if you plan to modify the tests:

```console
$ docker run -it --rm --privileged -v $PWD:/exttest \
             --privileged --shm-size 1024m \
             --name exttest exttest-dev
```

Inside the environment, you can start the tests like that:

```console
$ go test -v ./framework
```

Or, you can take a shortcut and start the tests immediately (again,
`-v $PWD:/exttest` is optional and is only needed if you plan to
modify the tests):

```console
$ docker run -it --rm --privileged -v $PWD:/exttest \
             --privileged --shm-size 1024m \
             --name exttest exttest-dev \
             go test -v ./framework
```
