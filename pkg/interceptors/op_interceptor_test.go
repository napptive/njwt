package interceptors

import (
	"context"
	"fmt"
	"github.com/napptive/analytics/pkg/analytics"
	"github.com/napptive/grpc-ping-go"
	"github.com/napptive/njwt/pkg/utils"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"net"
)

type pingAnalytics struct{}

func (p pingAnalytics) Ping(ctx context.Context, request *grpc_ping_go.PingRequest) (*grpc_ping_go.PingResponse, error) {

	// return the response
	return &grpc_ping_go.PingResponse{
		RequestNumber: request.RequestNumber,
		Data:          fmt.Sprintf("Ping [%d] received", request.RequestNumber),
	}, nil
}

var _ = ginkgo.Context("Operation interceptor", func() {

	if !utils.RunIntegrationTests("operation") {
		log.Warn().Msg("Analytics interceptor integration tests are skipped")
		return
	}

	var s *grpc.Server
	// gRPC test listener
	var lis *bufconn.Listener

	var client grpc_ping_go.PingServiceClient
	var provider analytics.Provider
	var proError error


	ginkgo.BeforeEach(func() {
		lis = bufconn.Listen(bufSize)

		// Create provider
		cfg, err := utils.GetBigQueryConfig()
		gomega.Expect(err).Should(gomega.Succeed())
		provider, proError = analytics.NewBigQueryProvider(*cfg)
		gomega.Expect(proError).Should(gomega.Succeed())

		s = grpc.NewServer(WithServerOpInterceptor(provider))

		handler := pingAnalytics{}
		grpc_ping_go.RegisterPingServiceServer(s, handler)
		go func() {
			if err := s.Serve(lis); err != nil {
				log.Fatal().Errs("Server exited with error: %v", []error{err})
				return
			}
		}()

		conn, err := grpc.DialContext(context.Background(), "bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}), grpc.WithInsecure())
		gomega.Expect(err).Should(gomega.Succeed())

		client = grpc_ping_go.NewPingServiceClient(conn)

	})
	ginkgo.AfterEach(func() {
		// Flush data
		_ = provider.(*analytics.BigQueryProvider).SendLoginCache()
		s.Stop()
		lis.Close()
	})

	ginkgo.It("should be able add ", func() {

		newCtx := utils.CreateFullContext()

		// Create a context with the token
		request := grpc_ping_go.PingRequest{RequestNumber: 1}
		response, err := client.Ping(newCtx, &request)
		gomega.Expect(err).Should(gomega.Succeed())
		gomega.Expect(response).ShouldNot(gomega.BeNil())
		gomega.Expect(response.RequestNumber).Should(gomega.Equal(request.RequestNumber))
		gomega.Expect(response.Data).ShouldNot(gomega.BeEmpty())

	})


})
