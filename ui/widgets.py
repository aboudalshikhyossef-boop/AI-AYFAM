        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        panel = QRectF(12, 8, self.width() - 24, self.height() - 16)
        panel_path = QPainterPath()
        panel_path.addRoundedRect(panel, 24, 24)

        panel_fill = QLinearGradient(panel.topLeft(), panel.bottomRight())
        panel_fill.setColorAt(0.0, QColor(15, 23, 42, 30))
        panel_fill.setColorAt(0.5, QColor(15, 23, 42, 20))
        panel_fill.setColorAt(1.0, QColor(15, 23, 42, 24))
        painter.fillPath(panel_path, panel_fill)

        panel_glow = QRadialGradient(panel.center(), max(self.width(), self.height()) * 0.85)
        panel_glow.setColorAt(0.0, QColor(self.accent.red(), self.accent.green(), self.accent.blue(), 26))
        panel_glow.setColorAt(0.35, QColor(255, 255, 255, 8))
        panel_glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.fillPath(panel_path, panel_glow)

        edge = QLinearGradient(panel.topLeft(), panel.bottomRight())
        edge.setColorAt(0.0, QColor(220, 244, 255, 118))
        edge.setColorAt(0.5, QColor(220, 244, 255, 26))
        edge.setColorAt(1.0, QColor(220, 244, 255, 72))
        painter.setPen(QPen(QBrush(edge), 1.2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(panel_path)

        current_key = self.items[self.current_index][0]
        group_ar, group_en = self.GROUP_LABELS.get(current_key, ("التنقل", "NAVIGATION"))
        painter.setPen(QColor(self.accent.red(), self.accent.green(), self.accent.blue(), 225))
        painter.setFont(QFont("Tajawal", 9, QFont.Weight.DemiBold))
        painter.drawText(QRectF(20, 16, self.width() - 40, 18), Qt.AlignmentFlag.AlignCenter, group_ar)
        painter.setPen(QColor(226, 238, 250, 95))
        painter.setFont(QFont("DejaVu Sans", 7, QFont.Weight.Medium))
        painter.drawText(QRectF(20, 32, self.width() - 40, 14), Qt.AlignmentFlag.AlignCenter, group_en)

        painter.setPen(QPen(QColor(self.accent.red(), self.accent.green(), self.accent.blue(), 28), 1.0))
        painter.drawLine(QPointF(self.width() / 2, panel.top() + 24), QPointF(self.width() / 2, panel.bottom() - 50))

        visible = []
        for index, item in enumerate(self.items):
            offset = self._offset_for(index)
            if abs(offset) <= 2.15:
                visible.append((index, item, offset))
        visible.sort(key=lambda entry: abs(entry[2]), reverse=True)

        for index, item, offset in visible:
            _key, _label, icon, color = item
            center = self._item_center(index)
            angle = offset * 0.56
            depth = max(0.0, math.cos(angle))
            active = abs(offset) < 0.12
            hovered = index == self.hovered_index
            pulse = math.sin(self.pulse_phase + index * 0.83)
            scale = 0.76 + 0.24 * depth + 0.018 * pulse + (0.035 if active else 0)
            opacity = 0.52 + 0.48 * depth
            icon_size = 72 * scale
            painter.save()
            painter.setOpacity(opacity)
            painter.translate(center)
            painter.rotate(-offset * 7.0)
            painter.scale(scale, 0.68 + depth * 0.32)
            color_value = QColor(color)
            glow = QRadialGradient(QPointF(0, 0), 48)
            glow.setColorAt(0, QColor(color_value.red(), color_value.green(), color_value.blue(), int(18 + 12 * pulse)))
            glow.setColorAt(1, QColor(color_value.red(), color_value.green(), color_value.blue(), 0))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(glow)
            painter.drawEllipse(QPointF(0, 0), 48, 48)
            if active or hovered:
                fill = QColor(255, 255, 255, 22 if active else 14)
                border = QColor(color_value.red(), color_value.green(), color_value.blue(), 180 if active else 110)
                painter.setPen(QPen(border, 1.4 if active else 1.0))
                painter.setBrush(fill)
                tile_size = 80 if active else 74
                painter.drawRoundedRect(QRectF(-tile_size / 2, -tile_size / 2, tile_size, tile_size), 22, 22)
            pixmap = icon.pixmap(QSize(max(18, int(icon_size)), max(18, int(icon_size))))
            painter.drawPixmap(QRectF(-icon_size / 2, -icon_size / 2, icon_size, icon_size), pixmap, QRectF(pixmap.rect()))
            painter.restore()

        active_item = self.items[self.current_index]
        painter.setPen(QColor(active_item[3]))
        painter.setFont(QFont("Tajawal", 11, QFont.Weight.DemiBold))
        painter.drawText(QRectF(18, self.height() - 58, self.width() - 36, 24), Qt.AlignmentFlag.AlignCenter, active_item[1])
        painter.setPen(QColor(226, 238, 250, 115))
        painter.setFont(QFont("Tajawal", 9))
        painter.drawText(QRectF(18, self.height() - 34, self.width() - 36, 16), Qt.AlignmentFlag.AlignCenter,
                         f"{self.current_index + 1:02d}  /  {len(self.items):02d}")
