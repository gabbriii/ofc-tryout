package function

import (
    "log"

    "github.com/openfaas-incubator/go-function-sdk"
)

func Handle(req handler.Request) (handler.Response, error) {
    var err error

    return handler.Response{
        Body: []byte("Hello world!"),
        Header: map[string][]string{
            "X-Served-By": []string{"openfaas.com"},
        },
    }, err
}
