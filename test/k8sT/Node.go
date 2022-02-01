// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package k8sTest

import (
	"fmt"

	. "github.com/onsi/gomega"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = Describe("K8sNode", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{})

		_, err := kubectl.CiliumNodesWait()
		ExpectWithOffset(1, err).Should(BeNil(), "Failure while waiting for k8s nodes to be annotated by Cilium")
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
	})

	It("Node labels updates are reflected in CiliumNode objects", func() {
		res := kubectl.Patch(helpers.DefaultNamespace, "node", helpers.K8s1, `{"metadata":{"labels":{"test-label":"test-value"}}}`)
		Expect(res).Should(helpers.CMDSuccess(), "Error patching %s Node labels", helpers.K8s1)

		var cn cilium_v2.CiliumNode
		err := kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("ciliumnode %s", helpers.K8s1)).Unmarshal(&cn)
		Expect(err).Should(BeNil(), "Can not retrieve %s CiliumNode %s", helpers.K8s1)

		Expect(cn.ObjectMeta.Labels["test-label"]).To(Equal("test-value"))

		res = kubectl.JsonPatch(helpers.DefaultNamespace, "node", helpers.K8s1, `[{"op": "remove", "path": "/metadata/labels/test-label"}]`)
		Expect(res).Should(helpers.CMDSuccess(), "Error patching %s Node labels", helpers.K8s1)

		var cn2 cilium_v2.CiliumNode
		err = kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("ciliumnode %s", helpers.K8s1)).Unmarshal(&cn2)
		Expect(err).Should(BeNil(), "Can not retrieve %s CiliumNode %s", helpers.K8s1)

		Expect(cn2.ObjectMeta.Labels["test-label"]).To(Equal(""))
	})
})
