package grpcapp

import (
	"fmt"
	"google.golang.org/grpc"
	"log/slog"
	"net"
	"os"
	authgRPC "sso/internal/grpc/auth"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

func New(log *slog.Logger, authService authgRPC.Auth, port int) *App {
	gRPCServer := grpc.NewServer()

	authgRPC.Register(gRPCServer, authService)

	return &App{
		log:        log,
		port:       port,
		gRPCServer: gRPCServer,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const fn = "app.grpcapp.Run"

	log := a.log.With(slog.String("fn", fn), slog.Int("port", a.port))

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", fn, err)
	}

	log.Info("gRPC server is running", slog.String("addr", l.Addr().String()))

	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", fn, err)
	}

	return nil
}

func (a *App) Stop(sign os.Signal) {
	const fn = "app.grpcapp.Stop"

	a.log.With(slog.String("fn", fn)).Info("stopping gRPC server", slog.String("signal", sign.String()))

	a.gRPCServer.GracefulStop()
}
