import torch
import torch.nn as nn


class CNNBranch(nn.Module):

    def __init__(self):
        super().__init__()

        self.net = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=3, padding=1),
            nn.BatchNorm1d(32),
            nn.ReLU(),

            nn.Conv1d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),

            nn.AdaptiveAvgPool1d(1)
        )

        self.fc = nn.Linear(64, 128)

    def forward(self, x):

        # [batch, 78] → [batch, 1, 78]
        x = x.unsqueeze(1)

        x = self.net(x)

        # [batch, 64, 1] → [batch, 64]
        x = x.squeeze(-1)

        x = self.fc(x)

        return x


class RFNNBranch(nn.Module):

    def __init__(self, input_size=78):
        super().__init__()

        self.net = nn.Sequential(

            nn.Linear(input_size, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.30),

            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.30),

            nn.Linear(128, 64),
            nn.ReLU()
        )

    def forward(self, x):
        return self.net(x)


class HybridModel(nn.Module):

    def __init__(self, input_size=78, num_classes=11):

        super().__init__()

        self.input_size = input_size
        self.num_classes = num_classes

        # CNN branch
        self.cnn = CNNBranch()

        # RFNN branch
        self.rfnn = RFNNBranch(
            input_size=input_size
        )

        # CNN 128 + RFNN 64 = 192
        self.fusion = nn.Sequential(

            nn.Linear(192, 128),
            nn.ReLU(),
            nn.Dropout(0.30),

            nn.Linear(128, num_classes)
        )

    def forward(self, x):

        # CNN representation
        cnn_features = self.cnn(x)

        # RFNN representation
        rfnn_features = self.rfnn(x)

        # Feature fusion
        fused_features = torch.cat(
            [cnn_features, rfnn_features],
            dim=1
        )

        # Final classification
        output = self.fusion(
            fused_features
        )

        return output