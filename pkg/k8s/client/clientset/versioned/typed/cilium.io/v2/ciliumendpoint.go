// Copyright 2017-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v2

import (
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// CiliumEndpointsGetter has a method to return a CiliumEndpointInterface.
// A group's client should implement this interface.
type CiliumEndpointsGetter interface {
	CiliumEndpoints(namespace string) CiliumEndpointInterface
}

// CiliumEndpointInterface has methods to work with CiliumEndpoint resources.
type CiliumEndpointInterface interface {
	Create(*v2.CiliumEndpoint) (*v2.CiliumEndpoint, error)
	Update(*v2.CiliumEndpoint) (*v2.CiliumEndpoint, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v2.CiliumEndpoint, error)
	List(opts v1.ListOptions) (*v2.CiliumEndpointList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v2.CiliumEndpoint, err error)
	CiliumEndpointExpansion
}

// ciliumEndpoints implements CiliumEndpointInterface
type ciliumEndpoints struct {
	client rest.Interface
	ns     string
}

// newCiliumEndpoints returns a CiliumEndpoints
func newCiliumEndpoints(c *CiliumV2Client, namespace string) *ciliumEndpoints {
	return &ciliumEndpoints{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the ciliumEndpoint, and returns the corresponding ciliumEndpoint object, and an error if there is any.
func (c *ciliumEndpoints) Get(name string, options v1.GetOptions) (result *v2.CiliumEndpoint, err error) {
	result = &v2.CiliumEndpoint{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("ciliumendpoints").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of CiliumEndpoints that match those selectors.
func (c *ciliumEndpoints) List(opts v1.ListOptions) (result *v2.CiliumEndpointList, err error) {
	result = &v2.CiliumEndpointList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("ciliumendpoints").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested ciliumEndpoints.
func (c *ciliumEndpoints) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("ciliumendpoints").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a ciliumEndpoint and creates it.  Returns the server's representation of the ciliumEndpoint, and an error, if there is any.
func (c *ciliumEndpoints) Create(ciliumEndpoint *v2.CiliumEndpoint) (result *v2.CiliumEndpoint, err error) {
	result = &v2.CiliumEndpoint{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("ciliumendpoints").
		Body(ciliumEndpoint).
		Do().
		Into(result)
	return
}

// Update takes the representation of a ciliumEndpoint and updates it. Returns the server's representation of the ciliumEndpoint, and an error, if there is any.
func (c *ciliumEndpoints) Update(ciliumEndpoint *v2.CiliumEndpoint) (result *v2.CiliumEndpoint, err error) {
	result = &v2.CiliumEndpoint{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("ciliumendpoints").
		Name(ciliumEndpoint.Name).
		Body(ciliumEndpoint).
		Do().
		Into(result)
	return
}

// Delete takes name of the ciliumEndpoint and deletes it. Returns an error if one occurs.
func (c *ciliumEndpoints) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("ciliumendpoints").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *ciliumEndpoints) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("ciliumendpoints").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched ciliumEndpoint.
func (c *ciliumEndpoints) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v2.CiliumEndpoint, err error) {
	result = &v2.CiliumEndpoint{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("ciliumendpoints").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
